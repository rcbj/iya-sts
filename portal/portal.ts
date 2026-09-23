'use strict';
//
// File: portal.ts
//
// ---------------------------------------------------------------------------
// THE USER PORTAL: THE FIRST PAGE IN THIS SERVICE THAT BELONGS TO THE PERSON
// LOOKING AT IT (2026-09-06).
//
// Every browser-facing surface here until now was for somebody else. The
// sign-in screen is a step in another protocol's flow; the consent screen asks
// one question and leaves; `/admin` is for an operator and is gated on two
// roles. **Nothing let a person see what this identity provider knows about
// THEM, or change how they authenticate.**
//
// **IT WAS ONE PAGE OF FOUR CARDS UNTIL 2026-09-06 AND IS FOUR PAGES BEHIND A
// NAVIGATION COLUMN NOW.** Four cards is a page; six is a scroll, and the
// control somebody came for is below the fold of a page about something else.
// `NAV` below is the page list, `navBar()` draws the column from it and
// `paths()` reports it to `sts_metadata.js`, so there is one copy of it —
// eight pages since 2026-09-13, and `portal/CLAUDE.md`'s table has every route.
// The first of them:
//
//   `/portal/activate?user=…&token=…`   UNAUTHENTICATED. Spending an activation
//                                       link to set up a credential. This is
//                                       how somebody provisioned through SCIM
//                                       or /admin-api comes to have a way in.
//   `/portal`                           AUTHENTICATED. The OVERVIEW: who they
//                                       are, this session, a summary of how
//                                       they sign in, and the wider sign-out.
//   `/portal/applications`              AUTHENTICATED. Where this identity
//                                       provider will sign them in — decided by
//                                       the SAME `common/issuance_gate.js` call
//                                       the nine issuance sites make, so this
//                                       page and those endpoints cannot
//                                       disagree. Each row LINKS to the
//                                       application's own home page where its
//                                       entry declares one, and is drawn greyed
//                                       out where it does not. See
//                                       applicationsFor() and linkedName().
//   `/portal/password`                  AUTHENTICATED. The form, and the POST
//                                       that answers it, on one path.
//   `/portal/keys`                      AUTHENTICATED. Their security keys.
//
// ---------------------------------------------------------------------------
// IT IS A SEPARATE APPLICATION FROM THE ADMIN CONSOLE AND SHARES NOTHING BUT
// THE SESSION STORE.
//
// Not the shell, not the navigation, not the gate. That is deliberate: the
// console's `respond()` draws a sidebar of forty administrative pages and its
// gate answers "does this person hold Admin Read" — neither of which is
// anything a person managing their own account should meet. **What they share
// is `authn.js`'s session store**, because there is one answer in this service
// to "who is this browser" and a second would be the thing that eventually
// disagrees. Since 2026-09-06 each is a relying party with its OWN session in
// that store (`portal/CLAUDE.md`).
//
// ---------------------------------------------------------------------------
// ACCESS CONTROL: THE IDENTITY COMES FROM THE SESSION AND NEVER FROM THE
// REQUEST. OWASP A01.
//
// This is the one rule in this file that matters more than the rest of it put
// together, and it is the vulnerability class that tops the Top Ten: **no route
// here takes a username, an id or a DN from the query string or the body.**
// Every page reads `sessionOf(req).user.username` and nothing else, so there is
// no parameter for anybody to change. `/portal/activate` is the single
// exception and it is not one: it takes a username BECAUSE nobody is signed in,
// and what authorises it is the token, which is a credential.
//
// `tests/portal_access.js` asserts it by trying — one session, another person's
// name in every parameter this file could plausibly have read.
//
// ---------------------------------------------------------------------------
// THE OWASP CONTROLS THIS PAGE CARRIES, and where each lives:
//
//   A01 access control    the rule above, plus `tests/portal_access.js`
//   A02 crypto            scrypt for passwords, the activation token hashed at
//                         rest — `common/credentials.ts`
//   A03 injection         every value through `esc()`; this service builds no
//                         SQL from user input anywhere
//   A04 insecure design   rate limiting on activation and password change —
//                         `common/websecurity.ts`
//   A05 misconfiguration  the CSP `app.js` sets on every response, including
//                         `script-src 'none'` and `frame-ancestors 'none'`
//   A07 auth failures     CSRF tokens on every POST here, session replaced on
//                         sign-in, and no message that distinguishes "no such
//                         person" from "wrong credential"
//   A09 logging           every act audited through `audit.js`
//
// A LIBRARY? No — it registers routes (rule 1), so its place in the route
// order is a place: `common/protocol_stack.ts` registers them (#50, R1). It
// must come AFTER `authn.js`, whose session it reads.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape, for a module that registers routes (rule 1):
//
//   * **`Portal` TAKES EVERY MODULE IT USES THROUGH ITS CONSTRUCTOR**
//     (`PortalDeps`): the shared express app, the helpers and the three
//     members of them this file always read (the logger, `parseBody()` and
//     `baseUrlOf()`), and every library required below. Nothing inside the
//     class reaches for a module on its own. The helpers that were free
//     functions are its methods now, and the directory slot is a field of it.
//   * **`registerRoutes(app)` HOLDS EVERY ROUTE AND THE ONE MIDDLEWARE, IN
//     THE ORIGINAL ORDER** — the token renewal on `/portal` first, then every
//     page and form target as this file has always registered them.
//   * **THE MODULE STILL EXPORTS `BASE`, `ACTIVATE`, `setDirectory` AND
//     `paths`**, as FACADES forwarding to the instance the composition root
//     builds (#50's R2); a process without the root builds a default at
//     load. Loading the module only logs where the portal is; it registers
//     NOTHING (#50, R1). The module exports a composite
//     `registerRoutes(app)` instead, which `common/protocol_stack.ts` calls at
//     the point in the route order where requiring this module used to
//     register the routes: the portal's own routes, and then
//     `portal/portal_certificates`, handed the pieces of a portal page — so
//     `/portal/certificates` is still registered after every other page of
//     the column. `ldap/ldap_server.js` still fills the slot through the
//     exported `setDirectory`, after the root has installed the instance.
//     `Portal` is exported beside it for that root.
//   * **THE VALIDATION SCHEMAS, THE STYLESHEET, `NAV` AND THE OTHER
//     CONSTANTS STAY AT MODULE SCOPE**, declared where they always were.
// ---------------------------------------------------------------------------

import app = require('../common/app');
import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import config = require('../common/config');
import mode = require('../common/mode');
import credentials = require('../common/credentials');
// The WebAuthn ceremony's options and this service's policy about what a key
// may BE, for the enrolment on /portal/keys. A LEAF (rule 3): it registers no
// route and requires only `config`, `helpers` and the verifier, so it can
// neither move a route nor close a cycle — and `credentials.js` above already
// requires it, so this is a second reader of one module rather than a new edge.
import webauthnPolicy = require('../authn/webauthn_policy');
// The mechanism itself, for the settings this page prints and the otpauth URI
// and QR code it draws. A LIBRARY (rule 3) that registers no route, and
// `credentials.js` above already requires it — so this is a second reader of
// one module rather than a new dependency in the require order.
import totp = require('../common/totp');
// THE RECOVERY CODES (2026-09-10). Required for its `settings()` and for
// `formatted()` — the printed rendering with the dashes in it, which is the
// one this service's own verifier is written to accept back. Drawing the
// grouping here would be a second copy of that agreement.
import backupCodes = require('../common/backup_codes');
// WHAT A PERSON IS, in the schema every person in this directory carries
// (2026-09-11). A LIBRARY (rule 3) reaching no further than
// `common/helpers.js`. It is the FIXED LIST the Overview's *You* section is
// drawn from, and the reason that section draws a list rather than the entry is
// in that file's header: an entry here carries whatever anybody put on it, and
// a page that printed it would print `stsTotpCredential` the day somebody
// enrolled an authenticator.
import inetOrgPerson = require('../common/inetorgperson');
// THE PERSON'S OWN RFC 7523 SIGNING KEY PAIR (2026-09-12), and the two modules
// behind `/portal/signing-key`. Both are LIBRARIES (rule 3) — neither registers
// a route, so requiring them here moves nothing — and the split between them is
// the one `/admin/pki` already has: `pki.js` ISSUES a key pair from this
// realm's Issuing CA and keeps no copy of it, and `person_assertions.js` owns
// what a person's key pair IS, where it is written and the one rule that comes
// with it — their key may assert about them and about nobody else.
//
// **THIS PAGE PERFORMS THE SAME ACT THE CONSOLE DOES, THROUGH THE SAME TWO
// FUNCTIONS**, which is the whole reason it is three requires rather than a
// call to `/admin-api`: one write path onto a person's entry, whoever pressed
// the button. A second implementation here would be a second answer to *what
// is on that entry after an issue*, and the two would agree until one of them
// grew an attribute.
import pki = require('../common/pki');
import personAssertions = require('../common/person_assertions');
// THE THIRD CARD ON `/portal/signing-key` (2026-09-13): a TLS client
// certificate. A LIBRARY (rule 3) over `common/pki.js` — it registers nothing,
// so this require moves no route.
import tlsClient = require('../common/tls_client_certificates');
import websecurity = require('../common/websecurity');
import authn = require('../authn/authn');
// THE RELYING PARTY (2026-09-06). This portal authenticates through the
// AUTHORIZATION CODE FLOW against this service's own authorization server now,
// as the registered client `sts-user-portal`, rather than by asking `authn.js`
// for a screen and reading the session that screen minted. `common/oidc_rp.ts`
// runs the flow and argues it; the section below is what changed here.
import oidcRp = require('../common/oidc_rp');
// WHICH REALM TO SIGN IN THROUGH (2026-09-14, #32). A library with no route,
// shared with the admin console.
import realmChooser = require('../common/realm_chooser');
// The realms, for where a sign-in link goes (`signInHref()`). A leaf here.
import realms = require('../common/realms');
// The access-control gate. A LEAF (rule 3), armed by xacml/xacml_access_pep.ts
// at 23c — before that line every check is allowed, which is what a process
// without the XACML family does.
import accessGate = require('../common/access_gate');
import audit = require('../common/audit');
// THE ERROR CODES (common/error_codes.js), a leaf. A refusal here marks its
// RESPONSE, which the call log reads after the bytes have gone, and carries the
// same code on the portal's own audit row where it writes one. Never on a page.
import errorCodes = require('../common/error_codes');

// The input validator. A LEAF (rule 3): it registers no route and requires only
// `config`, `bunyan` and zod, so it closes no cycle here and moves nothing.
import validation = require('../common/validation');
const vt = validation.types;
const vz = validation.z;
import stats = require('../common/admin_stats');

// ---------------------------------------------------------------------------
// THE REGISTRY AND THE ISSUANCE GATE, for `/portal/applications` (2026-09-06).
//
// Both are LIBRARIES (rule 3) and neither can move a route or close a cycle
// here: `common/applications.js` registers nothing — `admin-ui/admin.ts` and
// `ldap/ldap_server.js` draw its pages — and `common/issuance_gate.js` requires
// `helpers` and `config` and nothing else, which is the whole point of it being
// a leaf. Both are already loaded by `authn/authn.ts` at 8, above this module
// in `common/protocol_stack.ts`, so these two requires are cache hits.
//
// **THE GATE IS ASKED THE SAME QUESTION THE NINE ISSUANCE SITES ASK.** That is
// the property that makes the page worth having: a portal that worked out for
// itself which applications somebody may reach would be a SECOND
// implementation of the rule, and the first thing to disagree with the
// enforcement it is describing. See `applicationsFor()` below.
import applications = require('../common/applications');
import gate = require('../common/issuance_gate');
// THE VERSION, M.N.O, at the foot of every page here. A LEAF (rule 3):
// registers nothing and requires nothing from this repository. Read once at
// require time — it cannot change while the process runs. See
// common/version.js.
import version = require('../common/version');
// ---------------------------------------------------------------------------
// THIS PORTAL AS A SHARED SIGNALS RECEIVER (2026-09-10).
//
// A LIBRARY (rule 3): it registers no route, and the receive endpoint and the
// page below are registered HERE because a receiver hosts its own endpoint and
// a page belongs to the application it is a page of. It requires only other
// libraries, none of which requires this file, so it can sit at 8a without
// moving a route or closing a cycle — which matters more here than in the
// console, because this module is required BEFORE `oauth-oidc/oauth2.ts`.
//
// It is emphatically NOT `ssf/ssf.ts` (23b), which has every /ssf route and
// the well-known document: a require of that from here would have put the
// whole Shared Signals surface ahead of the authorization server. Since #50's
// R1 its own routes would stay where `common/protocol_stack.ts` registers
// them, but it would still load the console and `ldap/ldap_server.js` here,
// and that JavaScript module still registers its routes when required.
// ---------------------------------------------------------------------------
import signals = require('../ssf/ssf_receivers');
// WHAT SPENDING A PASSWORD RESET LINK SAYS OVER CAEP (2026-09-13). A LIBRARY
// that requires only the logger and reads `ssf/ssf.ts` out of the require cache
// when an event is due, so it moves no route from here — see its header.
import accountSignals = require('../ssf/account_signals');
// RISC section 2.8's register, for the account holder's own opt-out choice on
// /portal/signals (#146). A library that registers no route; the portal is
// loaded after the composition root defers instance building, so the require
// builds nothing early.
import risc = require('../ssf/risc');
const APP_VERSION = version.load();
const APP_BUILD_INFO = version.buildInfo(APP_VERSION);

const BASE = '/portal';
const ACTIVATE = BASE + '/activate';
// A PASSWORD RESET LINK an administrator issued (2026-09-13). Unauthenticated,
// like ACTIVATE, and for its reason: the token is the credential.
const RESET_PASSWORD = BASE + '/reset-password';

const CSS =
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
  'h1{margin:0}.pagehead form{margin:0}.pagehead ' +
  'button{margin-top:0}p.sub{color:#666;font-size:.9em;margin:0 0 ' +
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
  'font:inherit;background:#fff}' +
  'a.dl{display:inline-block;background:#2c5cc5;color:#fff;' +
  'text-decoration:none;border-radius:6px;padding:9px 14px;' +
  'margin:6px 8px 0 0;font-size:.9em}a.dl.secondary{background:#5a5a68}' +
  'ol.steps{margin:6px 0 0 1.2em;padding:0;font-size:.9em}' +
  'ol.steps li{margin:0 0 4px}' +
  '.state-valid{color:#1b7a3a;font-weight:600}' +
  '.state-revoked,.state-superseded{color:#b00020;font-weight:600}' +
  '.state-expired{color:#8a8a96;font-weight:600}' +
  '.ver code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}';

// ===========================================================================
// THE NAVIGATION, AND WHY THIS APPLICATION HAS ONE (2026-09-06).
//
// This portal was ONE PAGE holding four cards — who you are, how you sign in,
// change your password, sign out of everything — and it stopped being enough
// on the day it grew a fifth thing to say. Four cards is a page; six is a
// scroll, and the control somebody came for is below the fold of a page about
// something else.
//
// So it is a SHELL with a left-hand column now, the way the admin console has
// been since it had more than a handful of pages. **What it is not is the
// console's shell.** `admin.respond()` draws a sidebar of forty administrative
// pages, a realm chooser and a gate that asks whether this person holds Admin
// Read — none of which is anything somebody managing their own account should
// meet, which is the argument `portal/CLAUDE.md` has made since this directory
// existed. The console's markup is not exported and this one does not import
// it: two applications that look alike because they were built by the same
// hand, rather than two paths on one.
//
// THE TABLE IS THE PAGE LIST AND THERE IS NO SECOND COPY. `navBar()` draws it,
// `headingFor()` titles the page from it, and `paths()` at the foot of this
// file reports it to `sts_metadata.js` — so a page added here appears in the
// column, in the browser tab and in the endpoint list, and one removed leaves
// none of the three behind.
//
// **A SECTION IS PLAIN TEXT AND NEVER A LINK**, for the console's reason:
// there is no page behind it. It is a heading over the pages it groups.
// ===========================================================================
const NAV = [
  { title: 'Your account',
    what: 'What this identity provider knows about you, and where you can ' +
          'use it.',
    items: [
      { path: BASE, label: 'Overview', heading: 'Your account' },
      { path: BASE + '/applications', label: 'Applications',
        heading: 'Applications you can sign in to' },
      // SECURITY ACTIVITY (2026-09-10). Under *Your account* rather than under
      // *How you sign in*, and the two headings are the argument: that section
      // holds the CREDENTIALS on this person's entry, one page each, and every
      // page in it is a control. This is not a control and not about a
      // credential — it is what this identity provider has SAID about them,
      // to this portal, over the Shared Signals Framework. A reader arrives at
      // it asking what happened rather than asking to change something.
      { path: BASE + '/signals', label: 'Security activity',
        heading: 'Your security activity' }
    ] },
  { title: 'How you sign in',
    what: 'The credentials on your own entry, one page each.',
    items: [
      { path: BASE + '/password', label: 'Password',
        heading: 'Change your password' },
      { path: BASE + '/keys', label: 'Security keys',
        heading: 'Your security keys' },
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
        heading: 'Your certificates' }
    ] }
];

const NAV_PAGES = NAV.reduce(function (all, section) {
  return all.concat(section.items);
}, []);

// ---------------------------------------------------------------------------
// THE ACTIVATION FLOW. Unauthenticated, and the only route here that takes an
// identity from the request — because nobody is signed in yet and the TOKEN is
// what authorises it.
//
// **THE LINK IS NOT SPENT WHEN IT IS OPENED.** It is spent when the setup
// FINISHES. A link consumed on a GET would be burned by a browser prefetching
// it, by a corporate mail scanner following it, or by the person reloading the
// page — and each of those would strand somebody with an account they cannot
// set up and a link that no longer works.
// ---------------------------------------------------------------------------

// One sentence for every way an activation link can fail, and it is the SAME
// sentence. Wrong token, expired token, no token issued and no such person are
// four different facts and telling them apart would let anybody with the page
// enumerate which usernames have an activation outstanding.
const ACTIVATION_REFUSAL =
  'This activation link is not valid. It may have expired, it may already ' +
  'have been used, or it may never have been issued. Ask whoever set up your ' +
  'account for a new one.';

const ACTIVATE_QUERY = vz.object({
  user: vt.opt(vt.name),
  token: vt.opt(vt.token)
});

const ACTIVATE_FORM = vz.object({
  user: vt.opt(vt.name),
  token: vt.opt(vt.token),
  password: vz.string().max(1024).optional(),
  confirm: vz.string().max(1024).optional(),
  // The three radio values the form itself draws. A closed set rather than a
  // string, because this one decides what the enrolled key is FOR.
  key_role: vt.opt(vt.oneOf(['none', 'primary', 'mfa'])),
  // THE AUTHENTICATOR APP (2026-09-10). A checkbox rather than a fourth value
  // of `key_role`, because it is a SECOND factor beside whichever of those was
  // chosen and not one of the answers to *what signs you in*.
  totp: vt.opt(vt.flag),
  // WHICH OF THE TWO POSTS THIS IS. Setting up an authenticator takes a second
  // round trip — a secret has to be shown and a code typed back — and this
  // names it explicitly rather than being inferred from whether `code` is
  // present: a person who leaves the code box empty and presses Finish would
  // otherwise be treated as though they had started over.
  step: vt.opt(vt.oneOf(['setup', 'totp'])),
  code: vz.string().max(32).optional(),
  csrf_token: vt.opt(vt.token)
});

const PORTAL_QUERY = vz.object({
  done: vz.string().max(200).optional()
});

// The applications list, which is the one page here that is paginated. `page`
// is an INTEGER through `vt.integer()` rather than a string this file parses:
// the validator's job is that a handler never sees a shape it did not ask for,
// and a handler doing its own `parseInt` on a query string is the handler
// deciding what a bad value means — which is the split `common/validation.js`
// exists to keep. The upper bound is generous rather than tied to the row
// count, because the page count depends on what the policy permits THIS person
// and the validator cannot know it; `applicationsPage()` clamps to the last
// real page, which is what a bookmark to page 40 of a list that shrank to
// three should do.
const APPLICATIONS_QUERY = vz.object({
  done: vz.string().max(200).optional(),
  page: vt.opt(vt.integer(1, 100000))
});

const PASSWORD_FORM = vz.object({
  current: vz.string().max(1024).optional(),
  next: vz.string().max(1024).optional(),
  confirm: vz.string().max(1024).optional(),
  csrf_token: vt.opt(vt.token)
});

// A WebAuthn credential id is base64url, and it is the ONE identifier this
// surface takes from a body. It names a key on the SIGNED-IN person's own entry
// and is checked against that entry — the file's header calls this the case
// worth understanding, because it looks like the rule's exception and is not.
const REMOVE_KEY_FORM = vz.object({
  credentialId: vt.opt(vt.base64url),
  csrf_token: vt.opt(vt.token)
});

// ENROLLING ONE (2026-09-10). `credential` is the browser's ceremony result as
// JSON — a `vz.string()` here and parsed in the handler, exactly as
// `authn.js`'s WEBAUTHN_FORM carries it, because what is inside it is decided
// by the WebAuthn verifier and a schema here would be a second opinion about
// an object this file does not own.
const ENROL_KEY_FORM = vz.object({
  action: vt.opt(vt.oneOf(['begin', 'finish', 'cancel'])),
  role: vt.opt(vt.oneOf(['primary', 'mfa'])),
  label: vz.string().max(60).optional(),
  enrolment_id: vt.opt(vt.base64url),
  credential: vz.string().max(validation.CAP.TEXT).optional(),
  csrf_token: vt.opt(vt.token)
});

// ---------------------------------------------------------------------------
// A LINK'S CLAIM, HELD FOR THE LIFE OF ONE RESPONSE (2026-09-14, #46).
//
// `credentials.spendActivation()` / `spendPasswordReset()` claim a link in the
// store before the door sets anything, so two requests carrying one link — on
// two nodes, or racing on one — cannot both set a password. The claim is KEPT
// only by the request that FINISHES (`finishActivation()`, or the reset's
// success page), which marks the response; every other answer — a mismatched
// password, a refused code, the authenticator step drawn before the link is
// spent, a dropped connection — gives it back when the response ends, so the
// link works again exactly as it did on one node. `common/credentials.ts`
// argues the rest beside the two functions.
// ---------------------------------------------------------------------------
const LINK_SPENT = Symbol('portal.linkSpent');

// ---------------------------------------------------------------------------
// /portal/reset-password — SPENDING A PASSWORD RESET LINK (2026-09-13).
//
// An administrator pressed *Generate a password reset link* on this person's
// /admin/users page (or called POST /admin-api/users/issue-password-reset):
// their old password was removed, they were signed out of everything, and the
// link is how they choose a new one. It is the activation link's arrangement
// for somebody who already has an account, and it keeps every one of that
// link's properties, argued at `/portal/activate` above:
//
//   * **UNAUTHENTICATED, AND THE TOKEN IS WHAT AUTHORISES IT.** It takes a
//     username for that reason and no other.
//   * **RATE LIMITED on the GET and the POST**, in a bucket of its own.
//   * **ONE SENTENCE FOR EVERY FAILURE**, so nobody learns which usernames
//     have a link outstanding.
//   * **SPENT WHEN THE PASSWORD IS STORED**, not when the link is opened.
//   * **IT SIGNS NOBODY IN.** The last step is the ordinary sign-in screen,
//     reached through `/portal`, which is where a second factor they hold is
//     asked for.
//
// It does ONE thing, where the activation form offers a key and an
// authenticator as well: the person already has their second factors — an
// administrator took only the password away — and a form offering to enrol
// more on a link would be a way to add a second factor with nothing but the
// link.
//
// **THE PASSWORD GOES THROUGH `credentials.setPassword()`**, so product mode
// holds it to the realm's password policy and its history, which carries the
// password the link removed. `pwdReset` is cleared: a password the person just
// chose is not one they must change.
//
// **CAEP credential-change (`password`, `create`, initiated by the user)** is
// said when it is stored, through `ssf/account_signals.ts`.
// ---------------------------------------------------------------------------
const RESET_REFUSAL =
  'This password reset link is not valid. It may have expired, it may ' +
  'already have been used, or it may never have been issued. Ask whoever ' +
  'manages your account for a new one.';

const RESET_QUERY = vz.object({
  user: vt.opt(vt.name),
  token: vt.opt(vt.token)
});

const RESET_FORM = vz.object({
  user: vt.opt(vt.name),
  token: vt.opt(vt.token),
  password: vz.string().max(1024).optional(),
  confirm: vz.string().max(1024).optional(),
  csrf_token: vt.opt(vt.token)
});

// ---------------------------------------------------------------------------
// THE TWO PROFILES THIS PAGE ISSUES FOR (2026-09-13). RFC 7523's JWT bearer
// grant and RFC 7522's SAML 2.0 bearer grant are two key pairs on two attribute
// sets that share no name, so a person may hold either, both or neither, and
// each has its own Generate and its own Take off. The attribute names come
// from `personAssertions.KEY_PAIR_ATTRIBUTES` rather than being written here,
// so this page and `/admin/users?user=` cannot disagree about which attribute
// holds the handle.
//
// The words are the page's: what the key is for, the grant type a client
// names, and what the one-time card tells somebody to do with the private key.
// ---------------------------------------------------------------------------
const SIGNING_KEY_PROFILES = [
  { id: 'jwt', rfc: 'RFC 7523', title: 'JWT bearer grant',
    grantType: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
    document: 'a JSON Web Token' },
  { id: 'saml', rfc: 'RFC 7522', title: 'SAML 2.0 bearer grant',
    grantType: 'urn:ietf:params:oauth:grant-type:saml2-bearer',
    document: 'a SAML 2.0 assertion' }
];

// THE SIGNING KEY'S FORM (2026-09-12). Two actions and nothing else: there is
// no lifetime field, no algorithm field and — above all — no name field. The
// first two are deliberate simplicity (`pki.leafLifetimeDays` and the Issuing
// CA's own algorithm are the deployment's answers, and a person choosing an
// RSA modulus on their account page is a question nobody wants asked); the
// third is this file's rule, and it is the one that matters: a `username` here
// would let anybody signed in issue THEMSELVES a key pair on somebody else's
// entry, which is a takeover rather than a leak.
const SIGNING_KEY_FORM = vz.object({
  action: vt.opt(vt.oneOf(['generate', 'remove',
                          // A TLS client certificate (2026-09-13).
                          'generate-tls-client', 'revoke-tls-client'])),
  // THE TLS CLIENT CERTIFICATE'S FIELDS (2026-09-13). What the person calls the
  // device, the key algorithm from a closed list, the password protecting the
  // PKCS#12 twice over, and — for a revocation — the serial and one of two
  // reasons. Still NO NAME: the certificate is the session's person's, and the
  // serial is looked up among their certificates only.
  label: vz.string().max(80).optional(),
  key_alg: vt.opt(vt.oneOf(tlsClient.KEY_ALGS)),
  p12_password: vz.string().max(512).optional(),
  p12_confirm: vz.string().max(512).optional(),
  serial: vz.string().max(80).regex(/^[0-9A-Fa-f:]*$/).optional(),
  reason: vt.opt(vt.oneOf(tlsClient.REVOCATION_REASONS)),
  // WHICH PROFILE (2026-09-13): RFC 7523's JWT key pair or RFC 7522's SAML
  // one. Absent means `jwt`, which is what every form and client posted before
  // the second profile existed. A closed list, so anything else is refused at
  // the shape rather than reaching `common/pki.js`.
  purpose: vt.opt(vt.oneOf(['jwt', 'saml'])),
  csrf_token: vt.opt(vt.token)
});

const MFA_FORM = vz.object({
  action: vt.opt(vt.oneOf(['start', 'confirm', 'remove',
                          // The recovery codes, since 2026-09-11. `show-codes`
                          // is gone with the read-back it named: a set is
                          // hashed now and there is nothing to show.
                          'generate-codes', 'confirm-codes',
                          'discard-codes'])),
  // A STRING AND NOT AN INTEGER. `007123` is a code and 7123 is not: parsing a
  // one-time password as a number loses the leading zeros that one code in ten
  // has. The digit count is checked in `common/totp.ts`, where the person's own
  // enrolment says what it should be.
  code: vz.string().max(32).optional(),
  // THE PENDING SET'S HANDLE (2026-09-11). A set of recovery codes is
  // generated, shown, and stored only when the person confirms — and this is
  // what the Confirm and Throw-away forms carry back. A handle rather than the
  // username, so that two tabs cannot confirm each other's set; opaque, so
  // nothing here validates more than its length.
  //
  // **IT BELONGS TO THIS SCHEMA AND SPENT TEN MINUTES ON `ACTIVATE_FORM`.**
  // The two schemas end in identical lines, a first-occurrence edit put it on
  // the wrong one, and the symptom was not an error anywhere: the validator
  // simply dropped an unlisted field, so the Confirm button posted a handle
  // and the handler received an empty string and answered *there is no set
  // waiting to be confirmed*. Nothing logged, nothing threw, and the page
  // looked like it had lost the codes.
  handle: vz.string().max(128).optional(),
  csrf_token: vt.opt(vt.token)
});

// ===========================================================================
// THE APPLICATIONS PAGE (2026-09-06): WHAT THIS PERSON CAN SIGN IN TO.
//
// Every other page in this application is about the person. This one is about
// what the person can DO with the account — and it is the first page in this
// service to put the registry and the issuance policy together and answer a
// question a person rather than an operator would ask.
//
// ---------------------------------------------------------------------------
// IT ASKS THE ISSUANCE GATE, AND THAT IS THE WHOLE DESIGN.
//
// `common/issuance_gate.js` is the one place this service asks "may I issue
// this?", and the nine issuance sites — the token endpoint, both SAML
// profiles, WS-Federation, WS-Trust, the KDC — ask it exactly this way. So
// this page asks it too, once per application, and reports the answer.
//
// **The alternative was a second implementation of the rule and it is the one
// thing this page must not be.** Reading `appRequiredRole` off each entry and
// comparing it with `roles.rolesOf()` would work today, would be shorter, and
// would be the first thing to disagree with the enforcement the moment
// somebody edits the issuance policy on `/admin/xacml/policies` — a page
// telling a person they may sign in to something the token endpoint then
// refuses. There is one rule and one evaluator, and this is a reader of it.
//
// A process with no XACML family loaded has no decider, `check()` answers
// allowed, and this page lists everything with a sign-in family. That is the
// same "a smaller service rather than a broken one" the gate's own header
// argues, read from the outside.
//
// ---------------------------------------------------------------------------
// IT LISTS WHAT THE POLICY PERMITS, AND NAMES NOTHING IT DOES NOT.
//
// The refused entries are COUNTED and never named. That is the convention
// every enterprise account portal follows and it is the right one here for a
// reason of this service's own: the registry holds the applications of
// everybody who uses this identity provider, and a page that named them all to
// any signed-in person would be an application directory rather than an
// account page. What somebody is told is how many there are and who decides —
// which is true, useful, and names nobody.
//
// **It is not a security boundary and it is not offered as one.** `/admin-api`
// hands the whole registry to anybody holding an `admin:read` access token (and
// to anybody at all where `adminApi.authRequired` is off);
// `mgmt-api/CLAUDE.md` argues that gate. This is a page choosing not to answer
// a question it was not asked, which is a different thing from a page that
// could not answer it.
//
// ---------------------------------------------------------------------------
// AND IT IS A DRY RUN, WHICH THE GATE HAS TO BE TOLD.
//
// `preview: true` on the request. Nothing is being issued — somebody is
// looking at a page — so the refusals must not be written to the audit log as
// `xacml.issuance.refused` and must not be counted on `/admin/xacml/monitor`
// as decisions this service made. Drawing this page for a person with two
// permitted applications out of forty would otherwise write thirty-eight
// refusal rows into a 5,000-event ring on every page load, and read on the
// monitor as a service refusing issuance constantly.
//
// The flag is honoured in `xacml/xacml_role_pep.ts`, which is where the audit
// row and the counter are written; `issuance_gate.js` passes the request
// through untouched, so it needed no change at all. The console's own dry run
// at `/admin/roles` sets it now for the same reason — it had been writing
// refusal rows for issuances nobody asked for since it was written.
// ===========================================================================

// The families in which this service signs a PERSON in to an APPLICATION, and
// the issuance each one ends in. Ordered: a row reports its families in this
// order, and OpenID Connect comes before OAuth 2.0 because an entry carrying
// both is a relying party and the ID Token is what signs the person in.
//
// **WHAT IS DELIBERATELY NOT HERE.** WS-Trust issues a token FOR a relying
// party and Kerberos issues a service ticket, and both are real issuances the
// gate decides — but neither is a person signing IN to an application in a
// browser, which is the question this page asks. SSF receivers, SCIM clients,
// LDAP binders, SPIFFE workloads, OID4VP verifiers and mutual-TLS clients are
// not sign-in destinations at all. Everything left out is counted at the foot
// of the page rather than dropped silently.
const SIGN_IN_FAMILIES = [
  { protocol: 'oidc', kind: gate.ISSUANCE.ID_TOKEN, how: 'an ID Token' },
  { protocol: 'oauth2', kind: gate.ISSUANCE.ACCESS_TOKEN,
    how: 'an access token' },
  { protocol: 'saml2', kind: gate.ISSUANCE.SAML_ASSERTION,
    how: 'a SAML 2.0 assertion' },
  { protocol: 'saml11', kind: gate.ISSUANCE.SAML_ASSERTION,
    how: 'a SAML 1.1 assertion' },
  { protocol: 'wsfed', kind: gate.ISSUANCE.WSFED_TOKEN,
    how: 'a WS-Federation token' }
];

// How many entries the page will evaluate. Each entry costs one policy
// evaluation per distinct issuance kind it has, on the one thread that answers
// every socket this service holds — which is the stall `common/CLAUDE.md`'s
// worker-pool section is about, so the cap is here rather than left to be
// discovered. The page says when it bites.
//
// **THIS COMMENT CALLED IT "A GUARD AND NOT A SETTING" UNTIL 2026-09-12**, on
// the argument that a configuration row would be a knob nobody turns until the
// page had already been slow. The half about the page being slow is still
// true; what the argument left out is the deployment whose registry is past a
// thousand ON PURPOSE, which had no way to see its own applications at all
// short of editing this file. It is `portal.applicationScanLimit` now, with
// this number as its default, and it is read per request.
const SCAN_LIMIT = 1000;

// Rows per page. The registry is paginated for the same reason /admin's is:
// a list that draws every row is a list that stops working at some size and
// gives no sign of approaching it.
const PER_PAGE = 20;

// ===========================================================================
// YOUR SECURITY ACTIVITY — THIS PORTAL AS A SHARED SIGNALS RECEIVER
// (2026-09-10).
//
// `ssf/ssf_receivers.ts` holds the design and is not summarised here. Two
// things about it belong in THIS file, because they are this application's
// rules rather than that module's.
//
// **THE A01 RULE HOLDS AND THIS PAGE IS THE HARDEST CASE OF IT SO FAR.** No
// route here takes an identity from the request, which is easy to keep when
// every page reads the signed-in person's own entry. This page reads a queue
// that is about EVERYBODY: one stream delivers every CAEP and RISC event in
// the realm to this portal, because a receiver is told about the people it
// serves and there is exactly one of it. So the narrowing happens on the way
// OUT — `listFor(..., { person })` — and the person is composed from the
// session and from nothing else.
//
// **THE FILTER FAILS CLOSED, AND THAT IS `isAbout()`'s RULE RATHER THAN A
// SETTING.** An identifier it cannot resolve to a name — a phone number, an
// opaque id this service did not compose — is NOT a match. Showing one person
// another person's account lockout is a disclosure; failing to show somebody
// one of their own is an incomplete page, and those are not the same size of
// mistake. The foot of the page says so out loud, because a page that quietly
// hides things is worse than one that says it might be.
//
// **THERE IS NO CONTROL ON IT.** The console's inbox has a Clear; this one has
// none, and the reason is the one this whole directory is written under: a
// person cannot be allowed to erase the record of what was said about their
// own account. Clearing is an administrative act and lives where the
// administrative surface is.
// ===========================================================================

const SIGNALS_QUERY = vz.object({
  page: vt.opt(vt.integer(1, 100000))
});

// THE ACCOUNT HOLDER'S RISC PARTICIPATION (#146): one of section 2.8's three
// moves a person may make. opt-out-effective is not among them — only the
// scheduler job makes that move, after risc.optOutDelayHours.
const PARTICIPATION_FORM = vz.object({
  move: vz.enum(['optOutInitiated', 'optOutCancelled', 'optIn']).optional(),
  csrf_token: vt.opt(vt.token)
});

// What `ldap/ldap_server.js` hands `setDirectory()`: the one function this
// portal reads a directory entry through.
interface DirectoryHooks {
  personEntry(username: string): any;
  [member: string]: unknown;
}

// What the portal needs from the rest of the service. The modules are typed
// as `typeof` themselves, so this file checks the same whether each of them
// is JavaScript or TypeScript.
interface PortalDeps {
  app: typeof app;
  helpers: typeof helpers;
  config: typeof config;
  mode: typeof mode;
  credentials: typeof credentials;
  webauthnPolicy: typeof webauthnPolicy;
  totp: typeof totp;
  backupCodes: typeof backupCodes;
  inetOrgPerson: typeof inetOrgPerson;
  pki: typeof pki;
  personAssertions: typeof personAssertions;
  tlsClient: typeof tlsClient;
  websecurity: typeof websecurity;
  authn: typeof authn;
  oidcRp: typeof oidcRp;
  realmChooser: typeof realmChooser;
  realms: typeof realms;
  accessGate: typeof accessGate;
  audit: typeof audit;
  errorCodes: typeof errorCodes;
  validation: typeof validation;
  stats: typeof stats;
  applications: typeof applications;
  gate: typeof gate;
  signals: typeof signals;
  accountSignals: typeof accountSignals;
  risc: typeof risc;
  log: typeof helpers.log;
  parseBody: typeof helpers.parseBody;
  baseUrlOf: typeof helpers.baseUrlOf;
}

class Portal {
  static readonly BASE = BASE;
  static readonly ACTIVATE = ACTIVATE;

  constructor(private readonly deps: PortalDeps) {
    deps.log.debug("Entering Portal.constructor().");
    deps.log.debug("Leaving Portal.constructor().");
  }

  // What the composition root passes, from the real modules — what
  // loading this module passed before #50's R2.
  static defaultDeps(): PortalDeps {
    helpers.log.debug("Entering Portal.defaultDeps().");
    helpers.log.debug("Leaving Portal.defaultDeps().");
    return {
      app: app,
      helpers: helpers,
      config: config,
      mode: mode,
      credentials: credentials,
      webauthnPolicy: webauthnPolicy,
      totp: totp,
      backupCodes: backupCodes,
      inetOrgPerson: inetOrgPerson,
      pki: pki,
      personAssertions: personAssertions,
      tlsClient: tlsClient,
      websecurity: websecurity,
      authn: authn,
      oidcRp: oidcRp,
      realmChooser: realmChooser,
      realms: realms,
      accessGate: accessGate,
      audit: audit,
      errorCodes: errorCodes,
      validation: validation,
      stats: stats,
      applications: applications,
      gate: gate,
      signals: signals,
      accountSignals: accountSignals,
      risc: risc,
      log: helpers.log,
      parseBody: helpers.parseBody,
      baseUrlOf: helpers.baseUrlOf
    };
  }

  // The code a library already put on the result this portal is about to
  // report: the non-enumerable mark, or an `errorCode` member on an internal
  // result. Its own is the more specific; this portal's code names the door
  // otherwise.
  innerCode(result) {
    const { errorCodes, log } = this.deps;
    log.debug("Entering Portal.innerCode().");
    if (!result || typeof result !== 'object') {
      log.debug("Leaving Portal.innerCode().");
      return '';
    }
    log.debug("Leaving Portal.innerCode().");
    return errorCodes.codeOf(result) || String(result.errorCode || '');
  }

  // ===========================================================================
  // THE DIRECTORY, THROUGH AN INVERTED HOOK — THE FIRST SLOT THIS APPLICATION
  // HAS EVER OFFERED (2026-09-11).
  //
  // The Overview's *You* section answers *what does this identity provider hold
  // about me*, and until this it answered out of the SESSION: a username, a
  // subject, and whichever of `email` and `name` the sign-in happened to carry.
  // That is what the sign-in knew rather than what the directory holds, so a
  // person with a department, a manager and a room number on their entry saw
  // none of them.
  //
  // **IT IS A SLOT AND NOT A REQUIRE, AND RULE 3e'S TEST ANSWERS YES BOTH WAYS
  // ROUND**, which is the whole justification — that rule says a slot is what
  // you pay for a require that would close a cycle or move a route, and warns
  // against adding one by analogy:
  //
  //   * This module is required at 8a, before `oauth-oidc/oauth2.ts` at 9.
  //     `ldap/ldap_server.js` is at 21. A `require('../ldap/ldap_server')` here
  //     would register every `/ldap` route AND the eight `/admin/ldap/*`
  //     console pages at 8a — ahead of the authorization server, ahead of the
  //     console, ahead of the management API. That is rule 1 doing exactly what
  //     it says.
  //   * And a require the other way, from `ldap_server.js` to this module,
  //     would have moved every `/portal` route to 21 — behind the console and
  //     the management API — which was the same defect pointing the other
  //     way. **That half no longer holds since #50's R1**: requiring this
  //     module registers nothing, and `common/protocol_stack.ts` registers the
  //     `/portal` routes at 8a wherever the module is first loaded. The first
  //     half still holds, because `ldap_server.js` is JavaScript and still
  //     registers its routes when required; whether the slot is still worth
  //     its indirection is a question for when that module is converted.
  //
  // It carries ONE function and is validated whole for `setLogoutReader()`'s
  // reason: half of it is not a smaller feature, it is a page that reports an
  // empty account for a person whose entry plainly is not.
  //
  // **A PROCESS WITHOUT IT IS A SMALLER PORTAL RATHER THAN A BROKEN ONE.** The
  // section falls back to what it always drew — the session's four facts — and
  // says so on the page, which is the contract every other inverted hook in
  // this service keeps.
  // ===========================================================================
  private directory: DirectoryHooks | null = null;

  setDirectory(hooks) {
    const self = this;
    const { errorCodes, log } = this.deps;
    log.debug('Entering Portal.setDirectory().');
    if (!hooks || typeof hooks.personEntry !== 'function') {
      log.error(errorCodes.tag('STS-PORTAL-0014') +
                'portal: setDirectory() was given something without ' +
                'personEntry(), so it was refused whole. The Overview will ' +
                'go on drawing the four facts the session carries and will ' +
                'say that it is doing so.');
      log.debug('Leaving Portal.setDirectory(). Refused.');
      return false;
    }
    self.directory = hooks;
    log.debug('Leaving Portal.setDirectory(). The Overview reads the ' +
              'directory.');
    return true;
  }

  // ---------------------------------------------------------------------------
  // THE SIGNED-IN PERSON'S OWN ENTRY. **THE NAME COMES FROM THE SESSION AND
  // THERE IS NO PARAMETER FOR IT**, which is this application's whole rule and
  // matters as much here as on any form: this is the one function in the portal
  // that reads a directory entry, so a `username` reaching it from a request
  // would be every attribute of anybody's account, to anybody signed in.
  //
  // It takes the SESSION rather than a name for exactly that reason — there is
  // no call shape in which a caller supplies a string.
  // ---------------------------------------------------------------------------
  private entryFor(session) {
    const self = this;
    const { errorCodes, log } = this.deps;
    log.debug("Entering Portal.entryFor().");
    const username = session && session.user && session.user.username;
    log.debug('Entering Portal.entryFor(). username=' + username);
    if (!self.directory || !username) {
      log.debug('Leaving Portal.entryFor(). No directory, or no session.');
      return null;
    }
    let found = null;
    try {
      found = self.directory.personEntry(username);
    } catch (e) {
      // NOT rethrown. An account page that 500s because the store was mid-write
      // is worse than one that reports what the session knows — and the
      // fallback is a real one, said on the page.
      log.error(errorCodes.tag('STS-PORTAL-0015') +
                'portal: reading the directory entry for ' + username +
                ' threw, so the Overview is drawing what the session ' +
                'carries: ' + e.message);
      log.debug('Leaving Portal.entryFor(). It threw.');
      return null;
    }
    log.debug('Leaving Portal.entryFor(). ' +
              (found ? 'Found ' + found.dn : 'No entry.'));
    return found || null;
  }

  // Everything drawn here goes through it. The console has its own; this is a
  // separate application and shares no markup with it.
  esc(value) {
    const { log } = this.deps;
    log.debug("Entering Portal.esc().");
    log.debug("Leaving Portal.esc().");
    return String(value === undefined || value === null ? '' : value)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  private page(title, inner, wide?) {
    const self = this;
    const { log } = this.deps;
    log.debug("Entering Portal.page().");
    log.debug("Leaving Portal.page().");
    return '<!DOCTYPE html>\n<html lang="en"><head><meta charset="utf-8">' +
      '<meta name="viewport" content="width=device-width,initial-scale=1">' +
      '<title>' + self.esc(title) + ' — mock STS</title><style>' + CSS +
      '</style></head><body><div class="wrap' + (wide ? ' wide' : '') + '">' +
      inner +
      // WHICH BUILD THIS IS, on every page of this application including the
      // two that nobody is signed in for — the activation form and the
      // signed-out pages. It is in `page()` and not in `shell()` for exactly
      // that reason: the surfaces a person reaches when something has gone
      // wrong are the ones where "which build were you on" is most likely to be
      // asked, and those are precisely the pages `shell()` never draws.
      //
      // The provenance is in the tooltip rather than on the line. This is a
      // person's own account, not a console: the number is enough to quote, and
      // the build instant and commit are for whoever they quote it to.
      '<p class="ver" title="' + self.esc(APP_BUILD_INFO) + '">' +
      'mock-sts <code>' + self.esc(APP_VERSION.version) + '</code></p>' +
      '</div></body></html>\n';
  }

  // WHERE A "SIGN IN" LINK ON A PORTAL PAGE GOES (2026-09-14, #32). Every one
  // of them is drawn in the realm the person belongs to — an activation, a
  // reset, a sign-out — so the realm chooser has nothing to ask them. In a
  // trust realm `/portal` is rewritten under its prefix and the chooser never
  // applies; in the default realm, once realms are defined, `?realm=default` is
  // the choice already made.
  private signInHref() {
    const { log, realms } = this.deps;
    log.debug("Entering Portal.signInHref().");
    const skip = realms.isDefault() && realms.active();
    log.debug("Leaving Portal.signInHref(). " +
              (skip ? "Past the chooser." : "Plain."));
    return BASE + (skip ? '?realm=' +
      encodeURIComponent(realms.DEFAULT_ID) : '');
  }

  send(res, status, html) {
    const { log } = this.deps;
    log.debug("Entering Portal.send().");
    // `no-store` on every page: this one draws a person's own account details
    // and is reached from a shared browser as often as not.
    res.status(status).set('Cache-Control', 'no-store').type('html').send(html);
    log.debug("Leaving Portal.send().");
  }

  // The page's own title, read off the table rather than passed in at the call
  // site: a renamed page would otherwise be renamed in the column and not in
  // the heading over it, and the two would be right for exactly as long as
  // nobody looked.
  private headingFor(active) {
    const { log } = this.deps;
    log.debug("Entering Portal.headingFor().");
    const row =
        NAV_PAGES.filter(function (one) { return one.path === active; })[0];
    log.debug("Leaving Portal.headingFor().");
    return row ? row.heading : 'Your account';
  }

  private navBar(active) {
    const self = this;
    const { log } = this.deps;
    log.debug('Entering Portal.navBar(). active=' + active);
    const html = '<nav aria-label="Account pages">' +
      NAV.map(function (section) {
        const here = section.items.filter(function (item) {
          return item.path === active;
        }).length > 0;
        return '<div class="navsec' + (here ? ' open' : '') + '">' +
          '<p class="navhead" title="' + self.esc(section.what) + '">' +
          self.esc(section.title) + '</p><ul>' +
          section.items.map(function (item) {
            if (item.path === active) {
              // A SPAN AND NOT A LINK, and no `autofocus` on it — see the
              // stylesheet, where the console's reason for having one and this
              // application's reason for not is argued. `aria-current` is what
              // tells a screen reader the same thing the colour tells everybody
              // else.
              return '<li><span class="here" aria-current="page">' +
                     self.esc(item.label) + '</span></li>';
            }
            return '<li><a href="' + self.esc(item.path) + '">' +
                   self.esc(item.label) +
                   '</a></li>';
          }).join('') + '</ul></div>';
      }).join('') + '</nav>';
    log.debug('Leaving Portal.navBar(). ' + NAV.length + ' section(s).');
    return html;
  }

  // ---------------------------------------------------------------------------
  // ONE SIGNED-IN PAGE: the header, the column, and this page's cards.
  //
  // **THE SIGN OUT BUTTON IS IN THE HEADER AND SO IS ON EVERY PAGE.** It was in
  // the corner of the one page there was; it is in the corner of all of them
  // now, which is the same decision rather than a new one — a person who wants
  // out should not have to find the page it lives on first.
  //
  // `message` and `error` are drawn HERE rather than by each page, because
  // every page in this application can be reached carrying either: a redirect
  // after a successful write says so with `?done=`, and a refused write
  // re-draws the page it was posted from with the reason on it.
  // ---------------------------------------------------------------------------
  shell(active, session, message, error, cards) {
    const self = this;
    const { log, websecurity } = this.deps;
    log.debug('Entering Portal.shell(). active=' + active);
    const heading = self.headingFor(active);
    const csrf = websecurity.field(session.id);
    const html = self.page(heading,
      // THE HEADING AND THE SIGN OUT BUTTON IN ONE ROW, so that the control is
      // where a person looks for it — the top corner of the page they are on.
      // The wider sign-out is a card at the foot of the Overview page and says
      // which of the two reaches further; both are drawn, neither is quiet.
      '<header class="pagehead"><div><h1>' + self.esc(heading) + '</h1>' +
      '<p class="who">Signed in as <strong>' +
      self.esc(session.user.username) + '</strong></p></div>' +
      '<form method="post" action="' + BASE + '/signout">' + csrf +
      '<button class="secondary" title="' +
      self.esc('Ends this portal session and the sign-on session behind it — ' +
          'this browser\'s sessions. It does not revoke tokens or tickets ' +
          'already issued to applications; Sign out of everything, on the ' +
          'Overview page, does.') +
      '">Sign out</button></form></header>' +
      '<div class="shell">' +
      '<div class="side"><div class="card">' + self.navBar(active) +
      '</div></div>' +
      '<div class="main">' +
      (error ? '<div class="err">' + self.esc(error) + '</div>' : '') +
      (message ? '<div class="ok">' + self.esc(message) + '</div>' : '') +
      cards +
      '</div></div>', true);
    log.debug('Leaving Portal.shell(). ' + heading + '.');
    return html;
  }

  // ---------------------------------------------------------------------------
  // WHAT A PASSWORD HERE MUST BE, SAID ON THE FORM THAT ASKS FOR ONE
  // (2026-09-12).
  //
  // The rules are `common/password_policy.ts`'s default profile, read through
  // `credentials.passwordRules()` — the function the refusal is built beside —
  // so the sentence a person reads before typing and the rule applied after
  // they press the button are one rule. In development mode nothing is checked,
  // and the note says that rather than listing rules nobody applies.
  // ---------------------------------------------------------------------------
  private passwordRulesNote(username) {
    const self = this;
    const { credentials, log } = this.deps;
    log.debug("Entering Portal.passwordRulesNote().");
    const said = credentials.passwordRules(username);
    if (!said.enforced) {
      log.debug("Leaving Portal.passwordRulesNote().");
      return '<p class="note">This service is in development mode and checks ' +
             'no password, so any password is accepted here. In product mode ' +
             'it must be ' + self.esc(said.rules.join(', ')) + '.</p>';
    }
    log.debug("Leaving Portal.passwordRulesNote().");
    return '<p class="note">A password here must be ' +
           self.esc(said.rules.join(', ')) + '.</p>';
  }

  private activationForm(base, username, token, message, error) {
    const self = this;
    const { log, totp } = this.deps;
    log.debug("Entering Portal.activationForm().");
    const csrfless = ''; // the form carries the token instead; see below
    log.debug("Leaving Portal.activationForm().");
    return self.page('Set up your account',
      '<div class="card">' +
      '<h1>Set up your account</h1>' +
      '<p class="sub">You are setting up how <strong>' + self.esc(username) +
      '</strong> will sign in to <code>' + self.esc(base) + '</code>.</p>' +
      (error ? '<div class="err">' + self.esc(error) + '</div>' : '') +
      (message ? '<div class="ok">' + self.esc(message) + '</div>' : '') +
      '<form method="post" action="' + ACTIVATE + '">' +
      // THE TOKEN RIDES IN THE FORM, and this is the one place in this service
      // a credential is a hidden field. It is unavoidable: the person is not
      // signed in, so there is no session to carry state on, and the
      // alternative — a server-side pending record keyed by something else —
      // would be a second credential protecting the first. It is a POST so the
      // token does not end up in a referer or an access log the way a GET's
      // query string does.
      '<input type="hidden" name="user" value="' + self.esc(username) + '">' +
      '<input type="hidden" name="token" value="' + self.esc(token) +
      '"><h2>1. A ' +
      'password</h2><label for="password">Password</label><input ' +
      'type="password" id="password" name="password" ' +
      'autocomplete="new-password"><label for="confirm">Confirm ' +
      'it</label><input type="password" id="confirm" name="confirm" ' +
      'autocomplete="new-password">' +
      self.passwordRulesNote(username) +
      '<p class="note">Leave both empty if you would rather sign in with a ' +
      'security key alone. You need at least one of the two.</p><h2>2. A ' +
      'security key</h2><p class="note">A security key can be your ONLY ' +
      'credential (you sign in with the key and no password) or a SECOND ' +
      'factor beside a password. This service supports no other second ' +
      'factor.</p><label class="chk"><input type="radio" name="key_role" ' +
      'value="none" checked> No security key for now</label><label ' +
      'class="chk"><input type="radio" name="key_role" value="primary"> Use ' +
      'a security key instead of a password</label><label class="chk"><input ' +
      'type="radio" name="key_role" value="mfa"> Use a security key as a ' +
      'second factor, with the password above</label><p ' +
      'class="note">Choosing a security key takes you to the enrolment ' +
      'screen after this step.</p>' +
      // ---------------------------------------------------------------
      // THE AUTHENTICATOR APP (2026-09-10). A CHECKBOX AND NOT A FOURTH
      // RADIO BUTTON, and that is the whole of what it says about itself:
      // the radio group above is *what signs you in*, and exactly one of
      // its values can be true. An authenticator app is not one of those
      // answers — it is a SECOND factor beside whichever of them was
      // chosen, so it is an independent box.
      //
      // It appears whether or not `totp.enabled` is on and the DOOR
      // decides, exactly as the sign-in screen's anonymous button does...
      // no: it is DRAWN only when the mechanism is offered, because this
      // is a form somebody is filling in once and a tickbox that silently
      // does nothing is worse than an absent one. The door checks the
      // setting again regardless, because a form is markup.
      (totp.offered()
        ? '<h2>3. An authenticator app</h2><label class="chk"><input ' +
          'type="checkbox" name="totp" value="1"> Also set up an ' +
          'authenticator app as a second factor</label><p class="note">A ' +
          'six-digit code from Google Authenticator, Microsoft ' +
          'Authenticator, Authy, 1Password, Bitwarden, Aegis, FreeOTP or any ' +
          'other app that implements RFC 6238. <strong>It is a SECOND ' +
          'factor</strong> — it works beside the password or security key ' +
          'above and never instead of one. Ticking this shows you a QR code ' +
          'on the next step; your account is not set up until you type a ' +
          'code back from it.</p>'
        : '') +
      '<button type="submit">Continue</button>' +
      '</form>' +
      '</div>');
  }

  // ---------------------------------------------------------------------------
  // THE SECOND STEP OF AN ACTIVATION THAT ASKED FOR AN AUTHENTICATOR APP.
  //
  // **THE LINK IS NOT SPENT YET WHEN THIS IS DRAWN**, and that is the rule this
  // directory already had rather than a new one: a link is spent when the setup
  // FINISHES. Somebody who ticked the box, set a password, and then cannot find
  // their phone still holds a usable link — the password is set, so opening the
  // link again and leaving the box unticked completes the account.
  //
  // The token rides in the form for the same reason it does on the page before
  // this one: nobody is signed in, so there is no session to carry state on.
  // ---------------------------------------------------------------------------
  private activationTotpForm(username, token, enrolment, error) {
    const self = this;
    const { log } = this.deps;
    log.debug("Entering Portal.activationTotpForm().");
    log.debug("Leaving Portal.activationTotpForm().");
    return self.page('Set up your authenticator app',
      '<div class="card">' +
      '<h1>Scan this with your authenticator app</h1>' +
      '<p class="sub">Almost done. ' +
      '<strong>' + self.esc(username) + '</strong> has ' +
      'a password now; this adds the second factor.</p>' +
      (error ? '<div class="err">' + self.esc(error) + '</div>' : '') +
      (enrolment.qr
        ? '<p><img src="' + self.esc(enrolment.qr) + '" width="240" ' +
          'height="240" alt="QR code carrying this account\'s otpauth setup ' +
          'URI"></p>'
        : '') +
      '<h2>Or type it in</h2>' +
      '<table class="grid">' +
      '<tr><th>Secret</th><td><code>' + self.esc(enrolment.grouped) +
      '</code></td></tr><tr><th>Account</th><td><code>' + self.esc(username) +
      '</code></td></tr><tr><th>Issuer</th><td>' + self.esc(enrolment.issuer) +
      '</td></tr><tr><th>Algorithm</th><td>' +
      self.esc('HMAC-' +
          String(enrolment.algorithm).replace(/^SHA/, 'SHA-') + ', ' +
          String(enrolment.digits) + ' digits, every ' +
          String(enrolment.period) + ' seconds') + '</td></tr>' +
      '</table>' +
      '<form method="post" action="' + ACTIVATE + '">' +
      '<input type="hidden" name="user" value="' + self.esc(username) + '">' +
      '<input type="hidden" name="token" value="' + self.esc(token) + '">' +
      '<input type="hidden" name="step" value="totp">' +
      '<label for="code">The ' + self.esc(String(enrolment.digits)) +
      '-digit code your app is showing now</label>' +
      '<input type="text" id="code" name="code" autocomplete="one-time-code" ' +
      'inputmode="numeric" ' +
      'maxlength="' + self.esc(String(enrolment.digits)) + '" ' +
      'placeholder="' + '0'.repeat(enrolment.digits) + '"><button ' +
      'type="submit">Finish</button></form><p class="note">Nothing about the ' +
      'authenticator is stored until this code checks out, and your ' +
      'activation link is not used up until then either — so if you cannot ' +
      'finish now, open the link again and leave the authenticator box ' +
      'unticked.</p></div>');
  }

  // ---------------------------------------------------------------------------
  // WHAT THE PORTAL ROUTES TAKE, AND THE ONES THAT ARE ALLOWED A USERNAME.
  //
  // The rule at the top of this file is that no route here takes an identity
  // from the request — every page reads `sessionOf(req).user.username`, so
  // there is no parameter for anybody to change. **These schemas are the
  // mechanical statement of that rule**: only the unauthenticated link pages
  // declare an identity field, and a reader checking whether the rule still
  // holds can read short objects instead of handlers. (Some schemas sit beside
  // their handlers: `RESET_*`, `SIGNING_KEY_FORM`, `MFA_FORM`,
  // `SIGNALS_QUERY`.)
  //
  // `/portal/activate` is the exception and it is not one: it takes a username
  // BECAUSE nobody is signed in, and what authorises it is the token beside it,
  // which is a credential. `/portal/reset-password` (2026-09-13) is the same
  // case for the same reason.
  //
  // **`done` IS THE ONE REFLECTED VALUE ON THIS SURFACE.** This service puts it
  // in a `Location` after a successful change and reads it straight back onto
  // the page — so anybody can craft `/portal?done=<anything>` and have it
  // rendered. It is escaped through `esc()` and this page is `script-src
  // 'none'`, so the bound here is depth rather than the fix; what it removes is
  // the megabyte version and the one with a NUL in it.
  // ---------------------------------------------------------------------------
  // ---------------------------------------------------------------------------
  // A REFUSAL FROM `common/validation.js`, RENDERED AS A PAGE.
  //
  // That module returns a code, a field and a sentence and renders nothing;
  // this surface answers a person in a browser, so the sentence goes on a page
  // in this portal's own shell rather than into a JSON body nobody here would
  // see.
  //
  // 400 and not 403: nothing was refused about WHO is asking. The request was
  // malformed, which is true whether or not anybody is signed in — the same
  // line `common/validation.js` draws between shape and existence.
  // ---------------------------------------------------------------------------
  // error-code: none — the helper's definition, not a call to it.
  refuseShape(res, why) {
    const self = this;
    const { log } = this.deps;
    log.debug('Entering Portal.refuseShape(). code=' + why.code +
              ' field=' + why.field);
    log.debug('Leaving Portal.refuseShape().');
    // error-code: none — the shared renderer; every caller marks
    // STS-PORTAL-0001 before calling it
    return self.send(res, 400, self.page('Bad request',
      '<div class="card"><h1>Bad request</h1><p class="err">' +
      self.esc(why.detail) + '</p></div>'));
  }

  private holdLinkClaim(res, handle) {
    const { credentials, log } = this.deps;
    log.debug("Entering Portal.holdLinkClaim().");
    let settled = false;
    const settle = function () {
      log.debug("Entering settle().");
      if (settled) {
        log.debug("Leaving settle(). Already settled.");
        return;
      }
      settled = true;
      if (!res[LINK_SPENT]) {
        credentials.releaseLink(handle);
      }
      log.debug("Leaving settle().");
    };
    res.once('finish', settle);
    res.once('close', settle);
    log.debug("Leaving Portal.holdLinkClaim().");
  }

  private refuseSpentLink(req, res, username, spent, action, refusal, title) {
    const self = this;
    const { audit, errorCodes, log, websecurity } = this.deps;
    log.debug("Entering Portal.refuseSpentLink().");
    audit.record({
      category: 'authentication', action: action,
      errorCode: self.innerCode(spent) || 'STS-AUTHN-0183',
      actor: username, outcome: 'failure',
      summary: 'a link was refused: another request is spending it or has ' +
               'spent it',
      detail: { reason: spent.reason || '',
                address: websecurity.addressOf(req) }
    });
    errorCodes.mark(res, self.innerCode(spent) || 'STS-AUTHN-0183');
    log.debug("Leaving Portal.refuseSpentLink().");
    return self.send(res, 400, self.page(title,
      '<div class="card"><h1>' + self.esc(title) + '</h1><div class="err">' +
      self.esc(refusal) + '</div></div>'));
  }

  // ---------------------------------------------------------------------------
  // THE ONE PLACE AN ACTIVATION FINISHES (2026-09-10).
  //
  // **IT IS A FUNCTION BECAUSE THERE ARE THREE WAYS IN NOW** — a plain setup,
  // an authenticator confirmed on a second POST, and an authenticator that
  // could not be started — and every one of them has to spend the link, write
  // the audit row and draw the same page. Three copies of that is two chances
  // for one of them to leave a spent-looking link that still works.
  // ---------------------------------------------------------------------------
  private finishActivation(res, base, username, password, keyRole, withTotp,
                           req, warning?, recovery?) {
    const self = this;
    const { audit, backupCodes, credentials, log, websecurity } = this.deps;
    log.debug('Entering Portal.finishActivation(). username=' + username);
    // **THE LINK IS SPENT HERE**, once the account really can be used. Spending
    // it earlier would strand somebody whose password was refused. The mark
    // keeps the claim the POST took in the store (`holdLinkClaim()`).
    res[LINK_SPENT] = true;
    credentials.consumeActivation(username);
    audit.record({
      category: 'authentication', action: 'portal.activate',
      actor: username, outcome: 'success',
      summary: username + ' completed account setup',
      detail: { password: !!password, keyRole: keyRole, totp: !!withTotp,
                backupCodes: (recovery || []).length,
                address: websecurity.addressOf(req) }
    });
    log.info('portal: ' + username + ' completed account setup (' +
             (password ? 'password' : 'no password') + ', security key: ' +
             keyRole + ', authenticator app: ' + (withTotp ? 'yes' : 'no') +
             '). The activation link is now spent.');
    // CAEP credential-change for what setup created (#145): the first
    // password and the authenticator app, each a credential the person now
    // holds. A security key is enrolled later, by its own door.
    if (password) {
      self.deps.accountSignals.credentialChanged({ username: username,
        credentialType: 'password', changeType: 'create',
        initiatingEntity: 'user', via: 'portal activation',
        reasonAdmin: username + ' set a password when activating their ' +
                     'account.',
        reasonUser: 'You set a password for your new account.' });
    }
    if (withTotp) {
      self.deps.accountSignals.credentialChanged({ username: username,
        credentialType: self.deps.accountSignals.TOTP_CREDENTIAL_TYPE,
        changeType: 'create', initiatingEntity: 'user',
        via: 'portal activation',
        reasonAdmin: username + ' set up an authenticator app when ' +
                     'activating their account.',
        reasonUser: 'You set up an authenticator app.' });
    }

    // **THEY ARE SENT TO THE SIGN-IN SCREEN AND NOT SIGNED IN.** Spending an
    // activation link proves possession of a link, which is not the credential
    // they have just configured — and a link that both set up an account and
    // granted a session would be a standing bypass of every mechanism the
    // person chose. So the last step of setup is to use it.
    //
    // **AND THE LINK IS `BASE`, NOT `authn.LOGIN_PATH`, WHICH IS THE ONE RULE
    // THIS FILE ALREADY ARGUES AND THIS LINE BROKE.** `requireSignIn()` below
    // carries the whole of it: `/authn/login` is not a page anybody can be sent
    // to, because it draws a form for a PENDING AUTHENTICATION RECORD and
    // answers `There is no sign-in waiting under that id` to a request naming
    // none. So the last thing somebody did when setting up an account was press
    // a button labelled *Sign in* and meet an OAuth error page — the whole
    // activation flow ending in a refusal, on the one screen where a person's
    // first impression of this service is formed.
    //
    // Sending them to the PORTAL fixes it through the door that already exists:
    // `/portal` has no session, `requireSignIn()` calls
    // `beginAuthentication()`, and the screen is reached with a record behind
    // it. Two properties are worth keeping if this is ever reworked:
    //
    //   * **The record is minted when the link is PRESSED, not when this page
    //     is drawn.** Calling `beginAuthentication()` here and pasting the
    //     returned URL into the anchor would work and would then expire: a
    //     pending record has a lifetime, and somebody who sets a password and
    //     reads the page before clicking would meet the very error this
    //     replaces.
    //   * **They land on their own account page**, which is the right
    //     destination for somebody who has just set an account up — and the
    //     only destination this service can name, since an activation link
    //     belongs to no application and there is no flow in progress to resume.
    //
    // Both branches are therefore the same address, and the difference between
    // them is PROSE rather than a destination: with a key still to enrol they
    // are told why signing in comes first (enrolling one requires knowing who
    // is asking, and until they sign in nobody does).
    const next = self.signInHref();
    log.debug('Leaving Portal.finishActivation(). Set up; sending to sign in.');
    return self.send(res, 200, self.page('Account ready',
      '<div class="card"><h1>Your account is ready</h1>' +
      '<div class="ok">' +
      self.esc(password ? 'Your password is set.' : 'Your account is set up.') +
      ' This activation link has now been used and will not work again.</div>' +
      (warning ? '<div class="err">' + self.esc(warning) + '</div>' : '') +
      (withTotp
        ? '<p><strong>Your authenticator app is set up.</strong> You will be ' +
          'asked for a code every time you sign in, after your password — a ' +
          'password alone will not get you in any more. The code you just ' +
          'typed is spent, so wait for the next one.</p>'
        : '') +
      // ---------------------------------------------------------------------
      // THE RECOVERY CODES, ON THE ONE PAGE THIS PERSON WILL EVER SEE THEM
      // WITHOUT SIGNING IN (2026-09-10).
      //
      // **AND THAT IS EXACTLY WHY THEY ARE SHOWN HERE.** Everything else about
      // this screen is deliberately post-setup and pre-sign-in — the link is
      // spent, no session was granted, and the next thing that happens is a
      // sign-in. Somebody who has just enrolled an authenticator app and has
      // not yet signed in ONCE is the person most likely to be locked out by a
      // phone that goes wrong tonight, and telling them to sign in first and
      // find the list afterwards is advice that reaches the ones who do not
      // need it.
      //
      // **NO CALLER PASSES A SET SINCE 2026-09-11**: a set is hashed now and is
      // generated only on `/portal/mfa` (see the second-POST note in the
      // activation handler), so `recovery` is always empty and this branch
      // draws nothing. The prose inside it — "look at them again", "stored
      // encrypted" — describes the arrangement before that date.
      (recovery && recovery.length
        ? '<h2>Your recovery codes</h2>' +
          '<p><strong>Keep these somewhere you can reach without the device ' +
          'you just set up.</strong> Each one signs you in once, instead of ' +
          'a code from your authenticator app, when you cannot reach it. ' +
          'They are issued ONCE — this service will not make a new ' +
          'set.</p><ul class="codes">' +
          recovery.map(function (code) {
            return '<li><code>' + self.esc(backupCodes.formatted(code)) +
                   '</code></li>';
          }).join('') +
          '</ul>' +
          '<p class="note">You can look at them again on your ' +
          '<strong>Authenticator app</strong> page once you have signed in. ' +
          'This service stores them encrypted rather than hashed, which is ' +
          'why it can show them to you and why it can never show you your ' +
          'password.</p>'
        : '') +
      (keyRole !== 'none'
        ? '<p>You asked to use a security key' +
          (keyRole === 'mfa' ? ' as a second factor' : ' instead of a ' +
            'password') +
          '. A key is enrolled DURING A SIGN-IN rather than from your ' +
          'account pages: tick the security-key box at the sign-in screen ' +
          'and the first use enrols it. There is no enrol button on your ' +
          'Security keys page, because a WebAuthn ceremony belongs to a ' +
          'sign-in — which is the same reason nothing here links to ' +
          '/authn/webauthn.</p>'
        : '') +
      '<p><a href="' + self.esc(next) + '">Sign in</a></p></div>'));
  }

  private resetPasswordForm(base, username, token, error) {
    const self = this;
    const { log } = this.deps;
    log.debug("Entering Portal.resetPasswordForm().");
    log.debug("Leaving Portal.resetPasswordForm().");
    return self.page('Choose a new password',
      '<div class="card">' +
      '<h1>Choose a new password</h1>' +
      '<p class="sub">You are choosing the password <strong>' +
      self.esc(username) +
      '</strong> signs in to <code>' + self.esc(base) + '</code> with. Your ' +

      'old password no longer works.</p>' +
      (error ? '<div class="err">' + self.esc(error) + '</div>' : '') +
      '<form method="post" action="' + RESET_PASSWORD + '">' +
      // THE TOKEN RIDES IN THE FORM, for the activation form's reason: nobody
      // is signed in, so there is no session to carry it on, and a POST keeps
      // it out of a referer and an access log.
      '<input type="hidden" name="user" value="' + self.esc(username) + '">' +
      '<input type="hidden" name="token" value="' + self.esc(token) + '">' +
      '<label for="password">New password</label><input type="password" ' +
      'id="password" name="password" autocomplete="new-password">' +
      '<label for="confirm">Type it again</label><input type="password" ' +
      'id="confirm" name="confirm" autocomplete="new-password">' +
      self.passwordRulesNote(username) +
      '<button type="submit">Set my password</button>' +
      '</form></div>');
  }

  private refuseResetLink(res, status, code) {
    const self = this;
    const { errorCodes, log } = this.deps;
    log.debug("Entering Portal.refuseResetLink(). " + code);
    errorCodes.mark(res, code);
    log.debug("Leaving Portal.refuseResetLink().");
    return self.send(res, status, self.page('Password reset link',
      '<div class="card"><h1>Password reset link</h1><div class="err">' +
      self.esc(RESET_REFUSAL) + '</div></div>'));
  }

  // ---------------------------------------------------------------------------
  // THE AUTHENTICATED PORTAL.
  //
  // **THE IDENTITY COMES FROM THE SESSION AND NOWHERE ELSE.** Not from a query
  // parameter, not from a body field, not from a header. There is nothing here
  // for anybody to change, which is the only version of OWASP A01 that survives
  // somebody adding a page later without reading this comment.
  // ---------------------------------------------------------------------------
  requireSignIn(req, res, returnTo, want) {
    const self = this;
    const { accessGate, errorCodes, log, oidcRp, realmChooser } = this.deps;
    log.debug("Entering Portal.requireSignIn().");
    // THE PORTAL'S OWN SESSION AND NOT THE SIGN-ON SESSION (2026-09-06). This
    // is a relying party: it reads the session it established from an ID Token,
    // in its own cookie. `authn.sessionOf()` would be this portal reading the
    // identity provider's cookie, which is the arrangement the code flow
    // replaced — and it would also mean a person who signed in to any other
    // family here was silently already signed in to their account page, which
    // is single sign-on happening without an application ever having asked for
    // it.
    const session = oidcRp.sessionFor(req, 'portal');
    if (session) {
      // -------------------------------------------------------------------
      // AND THE POLICY (2026-09-06). OWASP A01, decided by the PDP.
      //
      // **THE STRUCTURAL RULE STAYS AND THIS IS NOT AN ALTERNATIVE TO IT.**
      // Taking the identity from the session rather than the request is how a
      // TRUSTWORTHY subject is obtained; the policy is what decides about that
      // subject. Reading the id from the request would mean the PDP faithfully
      // deciding about whoever the caller nominated, which is the same
      // vulnerability one layer up.
      //
      // **THE OWNER IS THE SUBJECT, HERE AND TODAY.** Every route on this page
      // is about the signed-in person's own account, so the resource's owner IS
      // `session.user.username` — and the policy's owner arm is what permits
      // it. That looks circular and is the point: it is written as a comparison
      // between two attributes rather than as an equality buried in a handler,
      // so a deployment that wants a HELPDESK ROLE able to manage somebody
      // else's account adds a rule instead of changing this file. Until then
      // the owner and the subject are the same name and the answer is the same
      // answer.
      const answer = accessGate.check({
        resource: accessGate.RESOURCE.PORTAL,
        action: want || accessGate.ACTION.MANAGE_OWN,
        subject: { name: session.user.username,
                   authenticated: session.authenticated !== false,
                   sessionId: session.id },
        owner: session.user.username,
        context: { method: req.method, path: req.originalUrl || req.url }
      });
      if (!answer.allowed) {
        log.info('portal: the access policy refused ' + req.method + ' ' +
                 (req.originalUrl || req.url) + ' for ' +
                 session.user.username + '. ' + answer.why);
        errorCodes.mark(res, self.innerCode(answer) || 'STS-PORTAL-0010');
        self.send(res, 403, self.page('Not permitted',
          '<div class="card"><h1>Not permitted</h1>' +
          '<div class="err">' + self.esc(answer.why) + '</div>' +
          '<p class="note">This is a policy decision rather than a missing ' +
          'sign-in. You are signed in as <strong>' +
          self.esc(session.user.username) + '</strong>.</p></div>'));
        log.debug("Leaving Portal.requireSignIn().");
        return null;
      }
      log.debug("Leaving Portal.requireSignIn().");
      return session;
    }
    // ---------------------------------------------------------------------
    // **THROUGH `beginAuthentication()` AND NOT A BARE REDIRECT TO THE LOGIN
    // PATH**, which is what this did at first and what does not work.
    //
    // `/authn/login` is not a page somebody can simply be sent to: it draws a
    // form for a PENDING AUTHENTICATION RECORD, and a POST that names no record
    // is answered `This sign-in form has expired`. Every other flow here enters
    // it the same way — `saml2_sso.ts`, `consent_screen.js`, `wsfed.ts` — by
    // asking this function for the address to send the browser to, and the
    // portal is no different from them in this respect even though it is not a
    // protocol.
    //
    // `returnTo` is a path on THIS service, which is what that function
    // requires and refuses anything else, so the portal cannot be used as an
    // open redirect by asking it to send somebody somewhere after signing in.
    // ---------------------------------------------------------------------
    // -------------------------------------------------------------------
    // **AND IT IS AN AUTHORIZATION CODE FLOW SINCE 2026-09-06.** Everything the
    // comment above says about not being able to redirect straight to
    // `/authn/login` is still true and is now true one layer down: this portal
    // does not reach for the sign-on session at all. It sends the browser to
    // `/oauth2/authorize` as `sts-user-portal`, and the sign-in screen is
    // reached — if it is reached at all — because the AUTHORIZATION ENDPOINT
    // decided it needed one. A person who already signed in somewhere else in
    // this service comes straight back with a code, which is single sign-on
    // falling out of the protocol rather than out of a shared cookie.
    //
    // **THE `application` SENTENCE ABOVE IS REVERSED AND THE ENTRY IS REAL.**
    // It said the portal is not an application — nobody registered it, it
    // issues no token, and naming one would put a fictional entry in the
    // registry. It IS one now: `sts-user-portal` is seeded under
    // `ou=applications` at startup (`applications.seedInternal`), it is what
    // the role gate is handed, and it is what a person consents to. What made
    // the old sentence right was that there was no such entry; what makes it
    // wrong now is that there is, and it was written by this service rather
    // than invented in a parameter.
    //
    // `returnTo` is still a path on this service, checked by `oidc_rp.js` the
    // way `beginAuthentication()` checked it AND held server-side, so the
    // portal still cannot be turned into an open redirect.
    // -------------------------------------------------------------------
    // WHICH REALM FIRST (2026-09-14, #32): a bare /portal on a service with
    // realms defined asks which realm the person belongs to before anything
    // sends them to sign in — `common/realm_chooser.ts`, shared with the
    // console. A choice is a redirect to that realm's own portal.
    const choice = realmChooser.decide(req, 'portal');
    if (choice && choice.kind === 'redirect') {
      res.set('Cache-Control', 'no-store').redirect(303, choice.location);
      log.debug("Leaving Portal.requireSignIn(). To the chosen realm.");
      return null;
    }
    if (choice && choice.kind === 'page') {
      if (choice.error) {
        errorCodes.mark(res, 'STS-PORTAL-0074');
      }
      self.send(res, choice.error ? 400 : 200, self.page('Choose your realm',
        '<div class="card"><h1>Choose your realm</h1>' +
        realmChooser.form(req, 'portal', choice.error) + '</div>'));
      log.debug("Leaving Portal.requireSignIn(). The realm chooser.");
      return null;
    }
    const begun = oidcRp.beginSignIn(req, res, 'portal', {
      returnTo: returnTo || BASE,
      fallback: BASE
    });
    // A promise under FAPI 1.0 Advanced (#139), where the request is signed
    // and pushed before the browser is sent; a value otherwise, answered in
    // the same tick as it always was.
    if (begun && typeof begun.then === 'function') {
      begun.then(function (started: any) {
        self.startedSignIn(res, started);
      });
      log.debug("Leaving Portal.requireSignIn(). Pushing.");
      return null;
    }
    self.startedSignIn(res, begun);
    log.debug("Leaving Portal.requireSignIn().");
    return null;
  }

  // What `requireSignIn()` does with the answer: nothing when the browser was
  // sent on, and the refusal page when it could not be.
  startedSignIn(res, started) {
    const self = this;
    const { errorCodes, log } = this.deps;
    log.debug("Entering Portal.startedSignIn().");
    if (!started.ok && !res.headersSent) {
      // The client entry is gone or has no secret. A refusal with the reason on
      // it rather than a redirect into a flow that cannot complete — and it
      // names the entry, because that is where somebody has to look.
      log.error(errorCodes.tag('STS-PORTAL-0011') +
                'portal: nobody can sign in. ' +
                started.why);
      // TWO CAUSES SINCE 2026-09-12, AND THE NOTE USED TO ASSERT THE FIRST. The
      // entry can be gone or secretless — "which is what has happened" — or, in
      // product mode, this portal can be reached at an address its entry does
      // not carry as a redirect URI, which `oidc_rp.js` now refuses rather than
      // writing onto the entry. The reason is in `started.why` either way; the
      // note only says which kind of fix it is.
      errorCodes.mark(res, self.innerCode(started) || 'STS-PORTAL-0011');
      self.send(res, 503, self.page('The portal cannot sign anybody in',
        '<div class="card"><h1>The portal cannot sign anybody in</h1>' +
        '<div class="err">' + self.esc(started.why) + '</div><p ' +
        'class="note">This portal signs people in through this service\'s ' +
        'own authorization server, as the registered client ' +
        '<code>sts-user-portal</code>. That entry is seeded at startup and ' +
        'lives under <code>ou=applications</code> like any other ' +
        'application, so it can be edited and deleted like any other' +
        (started.reason === 'unregistered-address'
          ? ' &mdash; and in product mode the addresses it may be reached at ' +
            'are the redirect URIs on it, which an administrator registers ' +
            'rather than a request.'
          : ' &mdash; which is what has happened.') +
        '</p></div>'));
    }
    log.debug("Leaving Portal.startedSignIn().");
  }

  // ---------------------------------------------------------------------------
  // THE OVERVIEW. What this identity provider knows about the person looking at
  // it, and the one act that reaches further than the button in the header.
  //
  // **IT NO LONGER HOLDS THE PASSWORD FORM OR THE KEY LIST**, which moved to
  // pages of their own when this application grew a column. What is left here
  // is a SUMMARY of both with a link to each — two facts and two links, rather
  // than two forms — because "have I got a password, and is a second factor
  // turned on" is the first thing somebody wants from an account page and the
  // last thing they want to hunt for.
  // ---------------------------------------------------------------------------
  // ===========================================================================
  // EVERY STANDARD inetOrgPerson ATTRIBUTE, ON THE PERSON'S OWN ACCOUNT PAGE
  // (2026-09-11).
  //
  // The *You* section used to be four facts read off the SESSION — a username,
  // a subject, and whichever of `email` and `name` the sign-in happened to
  // carry. That is what the sign-in knew rather than what this identity
  // provider holds, so somebody with a department, a manager and a room number
  // on their entry saw none of them on the page whose heading is *What this
  // identity provider knows about you*.
  //
  // ---------------------------------------------------------------------------
  // IT DRAWS A FIXED LIST AND LOOKS EACH NAME UP. IT DOES NOT PRINT THE ENTRY.
  //
  // The obvious implementation is to iterate the stored attributes, and it is
  // the one thing this block must not do. **An entry in this directory carries
  // whatever anybody put on it**: a TLS client certificate's subject becomes
  // attributes RDN by RDN, SCIM writes its own mapping, an `ldapadd` on 389
  // writes anything at all — and this service puts four `sts`-prefixed
  // CREDENTIALS on that same object. A page that printed the entry would print
  // `stsTotpCredential`, a shared secret, the day somebody enrolled an
  // authenticator, with nothing anywhere having decided that it should.
  //
  // So `common/inetorgperson.ts` is the list and this is a reader of it. A new
  // attribute this service invents cannot appear here by accident, and that is
  // a property of the list rather than of anybody remembering.
  //
  // ---------------------------------------------------------------------------
  // THE TWO REFUSALS ARE NOT MADE HERE, WHICH IS DELIBERATE.
  //
  // `userPassword` is on the `person` MAY list, so a faithful reading of the
  // schema puts it on this page, and the five binary attributes would arrive as
  // octets interpolated into HTML — one of which, `userPKCS12`, conventionally
  // carries a PRIVATE KEY. **`inetorgperson.rowFor()` refuses both** and this
  // block only renders what it is handed, so a second surface that ever draws
  // this list gets the same refusals without having to know about them.
  //
  // ---------------------------------------------------------------------------
  // THE EMPTY ONES ARE DRAWN TOO, BEHIND A `<details>`, AND THAT IS THE WHOLE
  // LAYOUT DECISION.
  //
  // Fifty attributes on an account page where a typical person holds six would
  // be a wall of nothing, and showing only what is set would answer *what does
  // this provider know about me* without ever saying what it COULD know — which
  // on a service that exists to be explored is the more useful half. So the
  // ones with values are drawn plainly and the rest are one fold per object
  // class, counted in the summary.
  //
  // **`<details>` IS MARKUP AND NOT SCRIPT**, which is why it is available here
  // at all: every page of this portal but `/portal/keys` is
  // `script-src 'none'`, and the console made exactly this argument for its own
  // collapsible prose. There is no collapse-all and there will not be one; that
  // is the cost, and it is said on the console's page rather than worked around
  // here.
  //
  // ---------------------------------------------------------------------------
  // THE THREE OBJECT CLASSES ARE THE HEADINGS, rather than one alphabetical
  // list. "The inetOrgPerson attributes" IS the union of three classes —
  // `person`, `organizationalPerson`, `inetOrgPerson` — and a reader who does
  // not know that learns it from the page, which is worth more here than
  // tidiness.
  // ===========================================================================
  private directoryBlock(session, entry) {
    const self = this;
    const { inetOrgPerson, log } = this.deps;
    log.debug('Entering Portal.directoryBlock().');
    if (!entry) {
      // NO DIRECTORY, OR NO ENTRY — and the two are worth telling apart,
      // because one is a process without `ldap/ldap_server.js` loaded and the
      // other is a person this service has authenticated and never written
      // down. Both leave the page honest rather than empty, which is the
      // contract every inverted hook in this service keeps.
      log.debug('Leaving Portal.directoryBlock(). Nothing to draw.');
      // **THE SESSION'S OWN TWO FACTS ARE DRAWN HERE AND NOWHERE ELSE**, which
      // is the half of this fallback that is easy to get wrong. The table above
      // used to carry `email` and `name` off the session; they moved into this
      // block as `mail` and `cn`, so a process with no directory would have
      // lost them altogether — a page showing LESS than it did before the
      // feature that was meant to show more.
      const fallback = [
        session.user.email ? ['Email', session.user.email] : null,
        session.user.name ? ['Name', session.user.name] : null
      ].filter(Boolean);
      log.debug("Leaving Portal.directoryBlock().");
      return (fallback.length
        ? '<table>' + fallback.map(function (pair) {
            return '<tr><th>' + self.esc(pair[0]) + '</th><td>' +
              self.esc(pair[1]) +
                   '<div class="attr">' +
                   self.esc('from your session rather than from a directory ' +
                            'entry') +
                   '</div></td></tr>';
          }).join('') + '</table>'
        : '') +
        '<p class="note">' +
        self.esc('This service is not showing your directory entry. Either ' +
            'it is running without its embedded directory, or nothing has ' +
            'been written down about you yet — an account here gets an entry ' +
            'the first time it authenticates or is provisioned. What is ' +
            'above is what the sign-in itself carried.') + '</p>';
    }

    const described = inetOrgPerson.describe(entry.attributes);

    // ONE ROW. `values` is already a plain array of strings for everything but
    // the two refused kinds, which arrive with none — see the header.
    const row = function (one) {
      log.debug("Entering row().");
      let value;
      if (one.secret) {
        value = '<span class="set">set</span> <span class="sub">' +
                self.esc('— a scrypt hash rather than the value, and never ' +
                    'shown here') + '</span>';
      } else if (one.binary) {
        value = '<span class="set">set</span> <span class="sub">' +
                self.esc('— ' + one.bytes + ' bytes of binary' +
                    (one.count > 1 ? ' in ' + one.count + ' values' : '') +
                    ', not shown') + '</span>';
      } else if (one.count > 1) {
        // MULTI-VALUED IS THE ORDINARY CASE IN LDAP and a page that joined the
        // values with a comma would render a person with two email addresses as
        // one address containing a comma. They are a list.
        value = '<ul class="vals">' + one.values.map(function (v) {
          return '<li>' + self.esc(v) + '</li>';
        }).join('') + '</ul>';
      } else {
        value = self.esc(one.values[0] || '');
      }
      log.debug("Leaving row().");
      return '<tr><th title="' + self.esc(one.ldap + ' — ' + one.rfc +
               (one.note ? '. ' + one.note.replace(/\*\*/g, '') : '')) + '">' +
             self.esc(one.label) +
             (one.must ? ' <span class="must" title="' +
               self.esc('The schema REQUIRES this attribute on every person.') +
               '">required</span>' : '') +
             '</th><td>' + value +
             '<div class="attr"><code>' + self.esc(one.ldap) +
             '</code> &middot; ' + self.esc(one.rfc) + '</div></td></tr>';
    };

    const sections = described.classes.map(function (klass) {
      const set = klass.rows.filter(function (one) { return one.present; });
      const unset = klass.rows.filter(function (one) { return !one.present; });
      return '<h3 class="dirclass" title="' +
             self.esc(klass.name + ' — ' + klass.rfc + ', OID ' +
                      klass.oid + '. ' + klass.what) + '">' +
             '<code>' + self.esc(klass.name) + '</code> ' +
             '<span class="sub">' + self.esc(klass.held + ' of ' + klass.total +
               ' set') + '</span></h3>' +
             (set.length
               ? '<table>' + set.map(row).join('') + '</table>'
               : '<p class="note">' +
                 self.esc('Nothing on your entry from this class.') + '</p>') +
             (unset.length
               ? '<details><summary>' +
                 self.esc('The other ' + unset.length + ' this class allows') +
                 '</summary><table>' + unset.map(function (one) {
                   return '<tr><th title="' +
                          self.esc(one.ldap + ' — ' + one.rfc) +
                          '">' + self.esc(one.label) +
                          (one.must ? ' <span class="must">required</span>' :
                           '') +
                          '</th><td><span class="unset">not set</span>' +
                          '<div class="attr"><code>' + self.esc(one.ldap) +
                          '</code> &middot; ' + self.esc(one.rfc) +
                          '</div></td></tr>';
                 }).join('') + '</table></details>'
               : '');
    }).join('');

    log.debug('Leaving Portal.directoryBlock(). ' + described.held + ' of ' +
              described.total + ' set.');
    return '<h3 class="dirhead">Your directory entry</h3>' +
      '<p class="note">' +
      self.esc('Every attribute the schema this service files people under ' +
          'allows — ' + described.held + ' of ' + described.total +
          ' are set on your ' +
          'entry. It is a fixed list read from the schema rather than a dump ' +
          'of what your entry happens to carry, so a credential this service ' +
          'stores beside these cannot appear here.') +
      ' <code>' + self.esc('objectClass: top, person, organizationalPerson, ' +
                      'inetOrgPerson') + '</code></p>' +
      sections +
      '<p class="note">' +
      self.esc('Nothing on this page can be edited here. These are written ' +
          'by an operator, by SCIM, or over LDAP — this portal changes how ' +
          'you AUTHENTICATE and not what this directory records about you.') +
      '</p>';
  }

  private overviewPage(session, message, error) {
    const self = this;
    const { authn, credentials, log, stats, websecurity } = this.deps;
    log.debug('Entering Portal.overviewPage().');
    const username = session.user.username;
    const mechanisms = credentials.mechanismsFor(username);
    const csrf = websecurity.field(session.id);
    const detail = stats.userDetail ? stats.userDetail(username) : null;
    // THE PERSON'S OWN ENTRY, from the session's name and no parameter. Null
    // where no directory is installed, which the block below says out loud
    // rather than drawing an empty table.
    const entry = self.entryFor(session);
    // THE SIGN-ON SESSION'S account of how this person is signed in, not the
    // copy this portal session took from its ID Token: a step-up since then is
    // on the sign-on session and nowhere else (`authn.signOnFactsFor()`).
    const signOn = authn.signOnFactsFor(session);

    const html = self.shell(BASE, session, message, error,
      '<div class="card">' +
      '<h2>You</h2>' +
      '<p class="sub">What this identity provider knows about you, and how ' +
      'you signed in to this page.</p><table>' +
      '<tr><th>Username</th><td>' + self.esc(username) + '</td></tr>' +
      '<tr><th>Subject</th><td><code>' + self.esc(session.user.sub || '') +
        '</code></td></tr>' +
      (entry
        ? '<tr><th>Directory entry</th><td><code>' + self.esc(entry.dn) +
          '</code></td></tr>'
        : '') +
      '<tr><th>Signed in</th><td>' +
        self.esc(new Date(signOn.startedAt).toISOString()) +
      '</td></tr>' +
      (signOn.authentications > 1
        ? '<tr><th>Last authenticated</th><td>' +
          self.esc(new Date(signOn.authTime).toISOString()) + ' (' +
          signOn.authentications + ' authentications in this sign-in)' +
          '</td></tr>'
        : '') +
      '<tr><th>How</th><td>' +
      self.esc(signOn.amr.join(', ') || 'unstated') +
        ' (acr ' + self.esc(signOn.acr) + ')</td></tr>' +
      '<tr><th>This session ends</th><td>' +
        self.esc(new Date(session.expires || 0).toISOString()) + '</td></tr>' +
      (detail
        ? '<tr><th>Times you have signed in</th><td>' +
          self.esc(String(detail.authentications || 0)) + '</td></tr>'
        : '') +
      '</table>' +
      self.directoryBlock(session, entry) +
      '</div>' +

      '<div class="card">' +
      '<h2>How you sign in</h2>' +
      '<table>' +
      '<tr><th>Password</th><td>' +
        (mechanisms.password ? 'set' : '<em>none set</em>') +
        ' — <a href="' + self.esc(BASE + '/password') + '">change ' +
      'it</a></td></tr><tr><th>Security keys</th><td>' +
        (mechanisms.keys.length
          ? self.esc(String(mechanisms.keys.length)) + ' enrolled'
          : '<em>none enrolled</em>') +
        ' — <a href="' + self.esc(BASE + '/keys') + '">see them</a></td></tr>' +
      '<tr><th>Authenticator app</th><td>' +
        (mechanisms.totp
          ? (mechanisms.totpUsable ? 'enrolled' : 'enrolled, but not readable')
          : '<em>not set up</em>') +
        ' — <a href="' + self.esc(BASE + '/mfa') + '">set it up</a></td></tr>' +
      // THE WAY BACK (2026-09-10). It is reported as a COUNT rather than as a
      // yes, because the number is the whole of what a person needs from this
      // row: a set is issued once and is never topped up, so *3 of 10 left* is
      // an instruction and *issued* is not.
      '<tr><th>Recovery codes</th><td>' +
        (mechanisms.backupCodes && mechanisms.backupCodes.present
          ? (mechanisms.backupCodes.usable
              ? self.esc(String(mechanisms.backupCodes.remaining) + ' of ' +
                    String(mechanisms.backupCodes.total) + ' unused')
              : 'issued, but not readable')
          : '<em>none issued</em>') +
        ' — <a href="' + self.esc(BASE + '/mfa') + '">see them</a></td></tr>' +
      // WHICH FACTOR, AND NOT MERELY WHETHER. There are two of them since
      // 2026-09-10, they are asked for at different screens, and "required" on
      // its own leaves somebody unable to guess what they will be asked for.
      '<tr><th>Second factor</th><td>' +
        (mechanisms.mfaRequired
          ? self.esc('required — a password alone will not sign you in. You ' +
                'will be asked for ' +
                (mechanisms.secondFactor === 'webauthn'
                  ? 'your security key' + (mechanisms.totp
                      ? ', with a one-time code offered as the alternative'
                      : '')
                  : 'a code from your authenticator app') + '.')
          : 'not required') + '</td></tr>' +
      '</table>' +
      '</div>' +

      '<div class="card">' +
      '<h2>Sign out of everything</h2>' +
      '<form method="post" action="/logout">' + csrf +
      '<button class="secondary">Sign out of everything</button></form><p ' +
      'class="note">Ends every session you hold here, in every protocol, and ' +
      'tells the applications that can be told — access and refresh tokens, ' +
      'Kerberos tickets, credential offers, LDAP binds, the lot. <strong>The ' +
      'Sign out button at the top of every page is the narrower ' +
      'one</strong>: it ends this browser\'s sessions and leaves what has ' +
      'already been issued to applications alone. Two different acts, and ' +
      'this is the one that reaches further.</p></div>');
    log.debug('Leaving Portal.overviewPage().');
    return html;
  }

  // ---------------------------------------------------------------------------
  // THE PASSWORD PAGE. One form, and the argument for the field somebody signed
  // in already has to fill in anyway.
  // ---------------------------------------------------------------------------
  private passwordPage(session, message, error) {
    const self = this;
    const { credentials, log, websecurity } = this.deps;
    log.debug('Entering Portal.passwordPage().');
    const mechanisms = credentials.mechanismsFor(session.user.username);
    const csrf = websecurity.field(session.id);

    const html = self.shell(BASE + '/password', session, message, error,
      '<div class="card">' +
      '<p class="sub">' +
      (mechanisms.password
        ? 'You have a password set.'
        : 'You have NO password set. Setting one here needs the current one, ' +
          'which you do not have — so a password is set through an ' +
          'activation link from whoever administers this service, or at ' +
          '<code>/portal/activate</code>.') +
      '</p>' +
      '<form method="post" action="' + BASE + '/password">' + csrf +
      '<label for="current">Your current password</label><input ' +
      'type="password" id="current" name="current" ' +
      'autocomplete="current-password"><label for="next">New ' +
      'password</label><input type="password" id="next" name="next" ' +
      'autocomplete="new-password"><label for="confirm">Confirm ' +
      'it</label><input type="password" id="confirm" name="confirm" ' +
      'autocomplete="new-password">' +
      self.passwordRulesNote(session.user.username) +
      '<button type="submit">Change password</button></form><p ' +
      'class="note">Your current password is required even though you are ' +
      'already signed in: a session somebody left open on a shared machine ' +
      'must not be enough to take the account over.</p></div>');
    log.debug('Leaving Portal.passwordPage().');
    return html;
  }

  // ---------------------------------------------------------------------------
  // THE SECURITY KEYS PAGE. The list, and one Remove button per key.
  //
  // The credential id in each form is the ONE identifier this application takes
  // from a body, and `credentials.removeKey()` looks it up among THIS person's
  // own keys — see the file header, where that is argued as the case that looks
  // like the rule's exception and is not.
  // ---------------------------------------------------------------------------
  private keysPage(session, message, error, base) {
    const self = this;
    const { credentials, log, websecurity } = this.deps;
    log.debug('Entering Portal.keysPage().');
    const mechanisms = credentials.mechanismsFor(session.user.username);
    const csrf = websecurity.field(session.id);
    const keys = mechanisms.keys;

    const html = self.shell(BASE + '/keys', session, message, error,
      '<div class="card">' +
      '<p class="sub">' + (keys.length
        ? self.esc(String(keys.length)) + ' enrolled. ' +
          (mechanisms.mfaRequired
            ? 'One of them is marked as a second factor, so a password alone ' +
              'will not sign you in.'
            : 'None of them is marked as a second factor.')
        : 'You have no security keys enrolled.') + '</p>' +
      (keys.length
        ? '<table class="grid"><tr><th>Key</th><th>Role</th><th>Enrolled</th>' +
          '<th></th></tr>' +
          keys.map(function (one) {
            return '<tr><td>' +
              self.esc(one.label || 'security key') + '</td>' +
              '<td>' + self.esc(one.role) + '</td>' +
              '<td>' +
              self.esc(new Date(one.enrolledAt || 0).toISOString()
                .slice(0, 10)) +
              '</td><td>' +
              '<form method="post" action="' + BASE + '/remove-key">' + csrf +
              '<input type="hidden" name="credentialId" value="' +
              self.esc(one.credentialId) + '">' +
              '<button class="danger">Remove</button></form></td></tr>';
          }).join('') + '</table>'
        : '') +
      '<p class="note">A security key is either your ONLY credential (you ' +
      'sign in with the key and no password) or a SECOND factor beside a ' +
      'password. You cannot remove your last way in — set another one ' +
      'first.</p>' +
      (keys.length > 1
        ? '<p class="note"><strong>You hold ' + self.esc(String(keys.length)) +
          ' keys, which is the point.</strong> If one is lost, the others ' +
          'still sign you in — and you can remove the lost one from this ' +
          'page without asking anybody.</p>'
        : (keys.length === 1
            ? '<p class="note"><strong>You hold one key and no ' +
              'backup.</strong> If it is lost, an operator has to clear it ' +
              'for you before you can enrol another — there is deliberately ' +
              'no self-service reset of a credential you cannot produce. Add ' +
              'a second key now, on a different device, and you never need ' +
              'that conversation.</p>'
            : '')) +
      self.enrolBlock(session, mechanisms, base) +
      '</div>');
    log.debug('Leaving Portal.keysPage(). ' + keys.length + ' key(s).');
    return html;
  }

  // ===========================================================================
  // ADDING A KEY, AND THE PARAGRAPH THIS REPLACED WAS WRONG (2026-09-10).
  //
  // It read: *A key is enrolled DURING A SIGN-IN — tick the security-key box at
  // the sign-in screen, and the first use enrols — or when an activation link
  // is spent. There is no enrol button here, because a WebAuthn ceremony
  // belongs to a sign-in and this page is not one.*
  //
  // **THE PREMISE IS FALSE.** A WebAuthn ceremony belongs to whoever is asking,
  // and a signed-in person asking to register a credential is the ORDINARY
  // WebAuthn flow — it is how every real relying party does it. What belongs to
  // a sign-in is an ASSERTION.
  //
  // What the sentence cost was the whole reason WebAuthn has a credential id, a
  // multi-valued attribute in `credentials.js` and a `maxKeysPerPerson`
  // setting: **nobody could hold a BACKUP.** The sign-in screen's checkbox is
  // enrol-on-first-use and is reserved for people who hold no second factor yet
  // — correctly, because enrolling there for somebody who already holds one is
  // the bypass `authn/CLAUDE.md` argues — so there was exactly one key per
  // person and no door to add another. A lost key meant an operator clearing
  // it, which is a support queue rather than a security control.
  //
  // ---------------------------------------------------------------------------
  // THIS IS THE SEVENTH SCRIPTED PAGE IN THIS SERVICE, AND THE FIRST IN THIS
  // PORTAL. The argument has to be made from scratch and this is it.
  //
  // `app.js` sets `script-src 'none'` on everything, and the rule is that a
  // page gets an exception only when it CANNOT WORK WITHOUT ONE. Several
  // candidates have been refused on it (the root CLAUDE.md lists them) —
  // federation's outbound form, the two pictures, the console's collapsible
  // prose, and `/authn/totp`, which sits next door to a scripted page and still
  // had to argue its own case, among them.
  //
  // **A WEBAUTHN CEREMONY IS A BROWSER API CALL.** There is no markup that
  // invokes `navigator.credentials.create()`, no form that produces an
  // attestation object, and no server-side substitute — the private key is
  // generated inside the authenticator and never leaves it. That is the same
  // argument `/authn/webauthn` was granted its exception on, and it is the
  // whole of the case here.
  //
  // **IT IS THE SAME SCRIPT, NOT A SECOND ONE.** `/authn/webauthn.js` is a
  // static resource that reads its parameters off a `wa-data` element, so this
  // page emits the same element and the same three ids and points at it. One
  // implementation of the ceremony in the browser, for both pages — a second
  // copy would be a second place for the base64url handling to go wrong, and
  // that has already happened once in that file's history (see `authn.js`'s
  // WEBAUTHN_SCRIPT and its header about `split/join`).
  //
  // **THE BUTTON IS REAL AND IS LABELLED FOR A PERSON**, which every scripted
  // page here does: with the script blocked, pressing it posts a form that
  // answers *your browser did not run the ceremony* rather than doing nothing.
  // ===========================================================================
  private enrolBlock(session, mechanisms, base) {
    const self = this;
    const { authn, credentials, log, webauthnPolicy, websecurity } = this.deps;
    log.debug('Entering Portal.enrolBlock().');
    const username = session.user.username;
    const csrf = websecurity.field(session.id);
    const policy = webauthnPolicy.settings();
    const pending = credentials.pendingKeyEnrolmentFor(username);

    if (!policy.enabled) {
      log.debug('Leaving Portal.enrolBlock(). Security keys are switched off.');
      return '<h2>Add a security key</h2>' +
        '<p class="note">Security keys are switched off in this service, so ' +
        'no new one can be enrolled. Any key already on your account goes on ' +
        'working.</p>';
    }
    if (mechanisms.keys.length >= policy.maxKeysPerPerson) {
      log.debug('Leaving Portal.enrolBlock(). At the cap.');
      return '<h2>Add a security key</h2>' +
        '<p class="note">You hold ' + self.esc(String(mechanisms.keys.length)) +
        ' security keys, which is the most this service allows. Remove one ' +
        'first.</p>';
    }

    // ---------------------------------------------------------------------
    // STEP TWO, drawn only while a challenge is held. The ceremony is armed
    // here and nowhere else, so a reload of this page with nothing pending is
    // the form again rather than a ceremony against a challenge that has gone.
    // ---------------------------------------------------------------------
    if (pending) {
      // THE BASE IS PASSED IN AND NEVER RECOMPUTED HERE. A realm's base URL
      // carries a path and the RP ID is its HOST, which is the mistake
      // `authn.originOf()`'s header says is waiting to be made twice — so this
      // page asks the module that already gets it right, with the base the
      // REQUEST arrived on.
      const rpId = authn.rpIdOf(base);
      log.debug('Leaving Portal.enrolBlock(). A ceremony is armed.');
      return '<h2>Touch your security key</h2>' +
        '<p class="note">Your browser is about to ask for a security key. ' +
        '<strong>Use a DIFFERENT one from any already on your ' +
        'account</strong> &mdash; the point of a backup is that it is not in ' +
        'the same place as the original. An authenticator that is already ' +
        'enrolled will refuse.</p><div id="wa-data"' +
        ' data-challenge="' + self.esc(pending.challenge) + '"' +
        ' data-rpid="' + self.esc(rpId) + '"' +
        ' data-user="' + self.esc(username) + '"' +
        ' data-allow=""' +
        ' data-exclude="' + self.esc(pending.exclude.join(',')) + '"' +
        ' data-options="' +
        self.esc(JSON.stringify(webauthnPolicy.creationOptions(rpId))) +
        '"' +
        ' data-mode="create"></div>' +
        '<button id="wa-go" type="button">Register this security key</button>' +
        '<form method="post" action="' + BASE + '/keys" id="wa-form">' + csrf +
        '<input type="hidden" name="action" value="finish">' +
        '<input type="hidden" name="enrolment_id" value="' +
        self.esc(pending.id) + '">' +
        '<input type="hidden" name="credential" id="wa-credential">' +
        // THE REAL BUTTON. With the script blocked this is the whole mechanism,
        // and what it posts is a `finish` with no credential — which the
        // handler answers by saying the browser ran no ceremony, rather than by
        // appearing to do nothing.
        '<button class="secondary">My browser did not ask &mdash; tell me ' +
        'why</button></form><form method="post" ' +
        'action="' + BASE + '/keys">' + csrf +
        '<input type="hidden" name="action" value="cancel">' +
        '<button class="secondary">Cancel</button></form>' +
        '<p class="sub">Registering as: <strong>' +
        self.esc(pending.role === 'primary'
          ? 'your only credential (no password)' : 'a second factor') +
        '</strong>' +
        (pending.label ? ', labelled ' + self.esc(pending.label) : '') +
        '.</p>' +
        '<script src="' + authn.WEBAUTHN_SCRIPT_PATH + '"></script>';
    }

    // ---------------------------------------------------------------------
    // STEP ONE. The role is chosen HERE and carried on the pending record,
    // because the ceremony's answer says nothing about what was asked for.
    // ---------------------------------------------------------------------
    const roles = [];
    if (policy.mfaAllowed) {
      roles.push(['mfa', 'A second factor, beside my password',
                  mechanisms.password
                    ? 'You will be asked for it every time you sign in.'
                    : 'You have no password, so this key alone will not sign ' +
                      'you in — set a password as well.']);
    }
    if (policy.primaryAllowed) {
      roles.push(['primary', 'My only credential — no password',
                  'You sign in with the key and nothing else.']);
    }
    if (!roles.length) {
      log.debug('Leaving Portal.enrolBlock(). No role is allowed.');
      return '<h2>Add a security key</h2>' +
        '<p class="note">This service allows a security key in neither role ' +
        'at the moment, so none can be enrolled.</p>';
    }

    log.debug('Leaving Portal.enrolBlock(). The form is drawn.');
    return '<h2>Add a security key</h2>' +
      (mechanisms.keys.length
        ? '<p class="note">This registers a NEW authenticator. The ones you ' +
          'already hold are excluded from the ceremony, so touching a key ' +
          'that is already enrolled will refuse rather than adding a second ' +
          'row for the same device.</p>'
        : '') +
      '<form method="post" action="' + BASE + '/keys">' + csrf +
      '<input type="hidden" name="action" value="begin">' +
      '<label for="key-label">Name it (optional)</label>' +
      '<input type="text" id="key-label" name="label" maxlength="60" ' +
      'placeholder="the one on my keyring">' +
      roles.map(function (row) {
        return '<label class="chk"><input type="radio" name="role" value="' +
          self.esc(row[0]) + '"' +
          (row[0] === roles[0][0] ? ' checked' : '') + '> ' +
          self.esc(row[1]) + ' <span class="sub">' + self.esc(row[2]) +
          '</span></label>';
      }).join('') +
      '<button>Add a security key</button></form>';
  }

  // ===========================================================================
  // THE AUTHENTICATOR APP PAGE (RFC 6238), 2026-09-10.
  //
  // The first page in this portal that HANDS SOMEBODY A CREDENTIAL rather than
  // taking one, and the design follows from that one fact.
  //
  // ---------------------------------------------------------------------------
  // TWO STEPS, AND THE FIRST WRITES NOTHING.
  //
  // Pressing *Set up* mints a secret and holds it IN MEMORY;
  // `common/credentials.ts` writes the attribute only when a code proves the
  // app really has it. **An unconfirmed secret on somebody's entry would be a
  // second factor they cannot produce** — open this page, walk away, come back
  // tomorrow, and be locked out of your own account by a form you abandoned.
  // That is not a hypothetical: it is what a one-step enrolment does to anybody
  // whose phone is in another room.
  //
  // ---------------------------------------------------------------------------
  // THE QR CODE IS AN IMAGE THIS SERVER DREW, AND THE SECRET IS SHOWN BESIDE
  // IT.
  //
  // `script-src 'none'` covers this page (every page of this portal but
  // `/portal/keys`), so a QR library running in the browser was never an option
  // — `common/totp.ts`'s `qrSvgDataUri()` renders it here and it arrives as a
  // `data:` URI, which `img-src 'self' data:` already allows for the two OID4VC
  // offer pages.
  //
  // **THE TYPED SECRET IS NOT A FALLBACK NOBODY SEES.** It is drawn beside the
  // code, in groups of four, with the algorithm, digits and period written out
  // — because scanning is impossible in three ordinary situations: the phone IS
  // the browser showing this page, the desktop authenticator has no camera, and
  // a `localhost` QR code photographed from a screen still points at a host the
  // phone cannot reach. The last one is the common case for a mock.
  //
  // ---------------------------------------------------------------------------
  // THE SECRET IS SHOWN ON A PAGE, WHICH IS EXACTLY AS DANGEROUS AS IT SOUNDS,
  // AND THREE THINGS BOUND IT.
  //
  // It is `no-store` like every page here; it is only ever drawn for the
  // SIGNED-IN person and never for a name in a parameter (the rule at the top
  // of this file); and **it stops being shown the moment it is confirmed** —
  // the enrolled page reports that an app is set up and never the secret behind
  // it, so a browser left open on this page does not become a standing copy of
  // somebody's second factor. `totp.enrolmentTtlMinutes` is the fourth bound:
  // an unconfirmed secret expires.
  //
  // ---------------------------------------------------------------------------
  // ENROLLING AGAIN REPLACES, AND THE PAGE SAYS SO BEFORE IT DRAWS THE NEW
  // CODE.
  //
  // One secret per person — `common/credentials.ts` argues why, and it is a
  // fact about the protocol rather than a policy: a six-digit code names no
  // credential, so two secrets would mean trying both. Somebody who scans a
  // second code and leaves the first app configured has an authenticator that
  // silently stopped working, so the warning is on the button rather than in a
  // note underneath it.
  // ===========================================================================
  // `fresh` is the one moment the recovery codes are drawn — the response to
  // the `generate-codes` POST (since 2026-09-11 an enrolment issues none, and
  // `revealed` is kept only so an old caller's argument lands harmlessly; see
  // `backupCodesCard()`). It is passed IN rather than read here, for the reason
  // `enrolment` is: the list is a live credential and a page builder that
  // fetched it would draw it on every GET.
  private mfaPage(session, message, error, enrolment, fresh?, revealed?) {
    const self = this;
    const { credentials, log, totp, websecurity } = this.deps;
    log.debug('Entering Portal.mfaPage().');
    const username = session.user.username;
    const mechanisms = credentials.mechanismsFor(username);
    const csrf = websecurity.field(session.id);
    const live = totp.settings();
    const offered = totp.offered();

    // THE ENROLMENT IN PROGRESS, passed in rather than read here: the caller
    // has already awaited the QR code, and a page builder that returned a
    // promise would make every other page in this file async by contagion.
    const setup = enrolment && enrolment.ok ? enrolment : null;

    const enrolledCard =
      '<div class="card">' +
      '<h2>Status</h2>' +
      '<p class="sub">' +
      (mechanisms.totp
        ? (mechanisms.totpUsable
            ? self.esc('An authenticator app is set up. A password alone ' +
                  'will not sign you in — you will be asked for a code.')
            : self.esc('An authenticator app is enrolled, but this service ' +
                  'cannot read the enrolment, so it cannot check your codes. ' +
                  'An administrator has to clear it before you can set one ' +
                  'up again.'))
        : self.esc('No authenticator app is set up.')) + '</p>' +
      (mechanisms.totp && mechanisms.totpDetail
        ? '<table class="grid">' +
          '<tr><th>Set up</th><td>' +
          self.esc(new Date(mechanisms.totpDetail.enrolledAt || 0).toISOString()
            .slice(0, 10)) +
          '</td></tr>' +
          '<tr><th>Last used</th><td>' +
          self.esc(mechanisms.totpDetail.lastUsedAt
            ? new Date(mechanisms.totpDetail.lastUsedAt).toISOString()
              .slice(0, 19) + 'Z'
            : 'never') + '</td></tr>' +
          '<tr><th>Algorithm</th><td>' +
          self.esc('HMAC-' + String(mechanisms.totpDetail.algorithm || 'SHA1')
                .replace(/^SHA/, 'SHA-') + ', ' +
              String(mechanisms.totpDetail.digits || 6) + ' digits, every ' +
              String(mechanisms.totpDetail.period || 30) + ' seconds') +
          '</td></tr></table>' +
          '<form method="post" action="' + BASE + '/mfa">' + csrf +
          '<input type="hidden" name="action" value="remove">' +
          '<button class="danger">Remove it</button></form>' +
          '<p class="note">Removing it drops your account to one factor. It ' +
          'cannot lock you out — an authenticator app is never a way in by ' +
          'itself — but your password alone will sign you in again ' +
          'afterwards.</p>'
        : '') +
      '</div>';

    const setupCard = setup
      ? '<div class="card">' +
        '<h2>Scan this with your authenticator app</h2>' +
        '<p class="sub">Nothing is saved until you type a code back, so this ' +
        'is not set up yet.</p>' +
        // THE IMAGE, drawn on the server. `alt` says what it is rather than
        // repeating the secret: a screen reader announcing a shared secret
        // character by character in an open-plan office is not an improvement.
        '<p><img src="' + self.esc(setup.qr) + '" width="240" height="240" ' +
        'alt="QR code carrying this account\'s otpauth setup URI"></p><h3>Or ' +
        'type it in</h3><p class="note">If you cannot scan — the phone is ' +
        'showing this page, the app has no camera, or this service is on ' +
        '<code>localhost</code> and your phone cannot reach it — add the ' +
        'account by hand with these:</p><table ' +
        'class="grid"><tr><th>Secret</th><td><code>' + self.esc(setup.grouped) +
        '</code></td></tr><tr><th>Account</th><td><code>' + self.esc(username) +
        '</code></td></tr><tr><th>Issuer</th><td>' + self.esc(setup.issuer) +
        '</td></tr><tr><th>Type</th><td>Time ' +
        'based</td></tr><tr><th>Algorithm</th><td>' +
        self.esc('HMAC-' + String(setup.algorithm).replace(/^SHA/, 'SHA-')) +
        '</td></tr>' +
        '<tr><th>Digits</th><td>' + self.esc(String(setup.digits)) +
        '</td></tr>' +
        '<tr><th>Period</th><td>' + self.esc(String(setup.period)) + ' ' +
        'seconds</td></tr></table><h3>Then prove it works</h3><form ' +
        'method="post" action="' + BASE + '/mfa">' + csrf +
        '<input type="hidden" name="action" value="confirm">' +
        '<label for="code">The ' + self.esc(String(setup.digits)) +
        '-digit code your app is showing now</label>' +
        '<input type="text" id="code" name="code" ' +
        'autocomplete="one-time-code" ' +
        'inputmode="numeric" ' +
        'maxlength="' + self.esc(String(setup.digits)) + '" ' +
        'placeholder="' + '0'.repeat(setup.digits) + '"><button ' +
        'type="submit">Finish setting it up</button></form><p ' +
        'class="note">The code this service accepts here is SPENT — you will ' +
        'need the next one to sign in, which is RFC 6238 section 5.2 and is ' +
        'why a code never works twice.</p></div>'
      : '';

    const startCard = offered
      ? '<div class="card">' +
        '<h2>' + (mechanisms.totp ? 'Replace it' : 'Set one up') + '</h2>' +
        '<p class="sub">Use your favourite authenticator app — ' +
        '<strong>Google Authenticator, Microsoft Authenticator, Authy, ' +
        '1Password, Bitwarden, Aegis, FreeOTP, KeePassXC</strong> or any ' +
        'other. They all implement the same specification (RFC 6238), so any ' +
        'of them works and nothing here is tied to one.</p>' +
        (mechanisms.totp
          ? '<p class="note"><strong>Setting up a new one replaces the one ' +
            'you have.</strong> You hold one authenticator here and not a ' +
            'list, because a six-digit code says nothing about which app ' +
            'produced it. Delete the old account from your app afterwards — ' +
            'it will keep showing codes that no longer work.</p>'
          : '') +
        '<form method="post" action="' + BASE + '/mfa">' + csrf +
        '<input type="hidden" name="action" value="start">' +
        '<button' + (mechanisms.totp ? ' class="secondary"' : '') + '>' +
        (setup ? 'Start again with a new secret'
               : (mechanisms.totp ? 'Replace my authenticator app'
                                  : 'Set up an authenticator app')) +
        '</button></form>' +
        '</div>'
      : '<div class="card"><h2>Not available</h2>' +
        '<p class="sub">' +
        self.esc('Authenticator apps are turned off on this service. An ' +
            'operator turns them on with the totp.enabled setting.') +
        '</p></div>';

    const aboutCard =
      '<div class="card">' +
      '<h2>What this is</h2>' +
      '<p class="note">A <strong>time-based one-time password</strong> — RFC ' +
      '6238. Your app and this service hold the same secret and both compute ' +
      'the same ' + self.esc(String(live.digits)) + '-digit number from it ' +
      'and the clock, so the code proves you have the app without either of ' +
      'you sending the secret anywhere. It changes every ' +
      self.esc(String(live.period)) + ' seconds.</p><p ' +
      'class="note"><strong>It is a SECOND factor and never a first ' +
      'one.</strong> It cannot replace your password here, because this ' +
      'service holds the same secret your app does — which is fine for ' +
      'proving you still have the app, and is not something to hang a whole ' +
      'account on. That is the difference between this and a security key, ' +
      'which keeps a private key this service never sees.</p><p ' +
      'class="note">Codes are checked <strong>properly, in every ' +
      'mode</strong>. Most credentials on this mock are not — any password ' +
      'is accepted — but a one-time password verifier that accepted any six ' +
      'digits would not be a permissive one, it would be a broken one, and ' +
      'there would be nothing left to test a client against.</p></div>';

    // THE RECOVERY CODES (2026-09-10), between the authenticator's own cards
    // and the explanation. It is on THIS page rather than a page of its own
    // because it answers a question about the second factor — see
    // `backupCodesCard()`.
    const recoveryCard = self.backupCodesCard(session, fresh, revealed,
                                              mechanisms);

    const html = self.shell(BASE + '/mfa', session, message, error,
      enrolledCard + setupCard + startCard + recoveryCard + aboutCard);
    log.debug('Leaving Portal.mfaPage().');
    return html;
  }

  // ===========================================================================
  // THE RECOVERY CODES CARD (rewritten 2026-09-11).
  //
  // **FOUR STATES AND THE MIDDLE ONE IS NEW.** It used to have two — you have a
  // set, or you do not — because a set was created for you and could be read
  // back whenever you asked. Now:
  //
  //   1. **no set, and no second factor.** Nothing is offered: recovery codes
  //      stand in for a factor, and a way back from a door you have not walked
  //      through is a control with nothing behind it.
  //   2. **no set, and a second factor.** The prompt, and it is deliberately
  //      loud — this is the population the old automatic issue protected, and
  //      asking is all that is left.
  //   3. **SHOWN AND NOT YET CONFIRMED.** The codes, and one button. Nothing is
  //      stored, and the page says so in those words: what is on the screen is
  //      not yet a credential and works nowhere until the button is pressed.
  //   4. **confirmed.** Counts, and a Replace control that says what replacing
  //      costs before it is pressed.
  //
  // **THE THING THIS CARD MUST GET RIGHT IS STATE 3.** Somebody who writes the
  // codes down, closes the tab and never presses the button is holding a page
  // of strings that work nowhere — and would have no way of knowing. So the
  // confirm step is the ONLY thing on the screen at that moment, the codes are
  // labelled as not-yet-active, and the Cancel beside it says what it throws
  // away.
  // ===========================================================================
  private backupCodesCard(session, fresh, revealed, mechanisms) {
    const self = this;
    const { backupCodes, credentials, log, websecurity } = this.deps;
    log.debug("Entering Portal.backupCodesCard().");
    const username = session.user.username;
    log.debug('Entering Portal.backupCodesCard(). username=' + username);
    const live = backupCodes.settings();
    // THE CALLER'S ANSWER, PASSED IN — `mechanismsFor()` walks the directory
    // and asking twice on one render is a second walk for a number the caller
    // has.
    const status = (mechanisms || credentials.mechanismsFor(username))
                     .backupCodes || { present: false, remaining: 0, total: 0 };
    const advised = (mechanisms || credentials.mechanismsFor(username))
                      .recoveryAdvised;
    const csrf = websecurity.field(session.id);

    // ---------------------------------------------------------------------
    // STATE 3: a set has been generated and is being shown.
    //
    // `revealed` is gone as a parameter's meaning — nothing can be revealed —
    // and it is kept in the signature only so that a caller left over from an
    // older build passes `null` harmlessly rather than shifting the arguments.
    // ---------------------------------------------------------------------
    if (fresh && fresh.ok && fresh.codes && fresh.codes.length) {
      const list = fresh.codes.map(function (code) {
        return '<li><code>' + self.esc(backupCodes.formatted(code)) +
          '</code></li>';
      }).join('');
      log.debug('Leaving Portal.backupCodesCard(). Showing a pending set.');
      return '<div class="card">' +
        '<h2>Save these recovery codes</h2>' +
        '<p class="sub"><strong>' +
        self.esc('They are not saved yet. Nothing has been stored, and none ' +
            'of these codes will work until you press the button below.') +
        '</strong></p>' +
        '<ul class="codes">' + list + '</ul><p class="note"><strong>This is ' +
        'the only time they will ever be shown.</strong> When you confirm, ' +
        'this service stores a <em>hash</em> of each one &mdash; the same ' +
        'kind of scrypt hash it stores for your password &mdash; so it can ' +
        'check a code you type and can never print one back. Write them ' +
        'down, print them, or put them in a password manager first.</p><p ' +
        'class="note"><strong>Each code works once.</strong> Type one at the ' +
        'sign-in screen instead of your second factor when you cannot ' +
        'produce it. The dashes and the case do not matter; they are there ' +
        'so you can transcribe it.</p>' +
        (fresh.replacing
          ? '<p class="note"><strong>Confirming replaces the set you already ' +
            'have.</strong> Every code on your old list stops working the ' +
            'moment you press the button.</p>'
          : '') +
        '<form method="post" action="' + BASE + '/mfa">' + csrf +
        '<input type="hidden" name="action" value="confirm-codes">' +
        '<input type="hidden" name="handle" value="' +
          self.esc(String(fresh.handle || '')) + '">' +
        '<button>I have saved these codes</button>' +
        '</form>' +
        '<form method="post" action="' + BASE + '/mfa">' + csrf +
        '<input type="hidden" name="action" value="discard-codes">' +
        '<input type="hidden" name="handle" value="' +
          self.esc(String(fresh.handle || '')) + '">' +
        '<button class="secondary">Throw these away without saving</button>' +
        '</form>' +
        '<p class="note">If you close this page without confirming, nothing ' +
        'is stored and nothing changes &mdash; these codes simply never ' +
        'existed. Whatever set you had before is untouched.</p></div>';
    }

    // ---------------------------------------------------------------------
    // STATES 1, 2 AND 4.
    // ---------------------------------------------------------------------
    const generateForm =
      '<form method="post" action="' + BASE + '/mfa">' + csrf +
      '<input type="hidden" name="action" value="generate-codes">' +
      '<button' + (status.present ? ' class="secondary"' : '') + '>' +
      (status.present ? 'Generate a new set' : 'Generate my recovery codes') +
      '</button></form>';

    let body;
    if (!status.present) {
      body =
        '<p class="sub">' +
        self.esc(advised
          ? 'You have a second factor and no recovery codes. If you cannot ' +
            'reach it — a flat phone, a security key in a drawer at home — ' +
            'there is currently no way back into this account except an ' +
            'administrator.'
          : 'None have been generated. Recovery codes stand in for a second ' +
            'factor when you cannot produce it, so they are worth generating ' +
            'once you have one.') + '</p>' +
        (advised
          ? '<p class="note"><strong>This service will not create a set for ' +
            'you.</strong> It used to, as a side effect of enrolling a ' +
            'second factor &mdash; it cannot any more, because it now stores ' +
            'only a hash of each code and a hash can only be made while the ' +
            'code is on the screen in front of you.</p>'
          : '') +
        (live.enabled ? generateForm : '') +
        '<p class="note">' + self.esc(live.count + ' codes of ' + live.length +
          ' characters are generated. They are shown once, and stored only ' +
          'after you confirm you have saved them.') + '</p>';
    } else if (!status.usable) {
      body =
        '<p class="sub">' +
        self.esc('A set exists and this service cannot read it (' +
            (status.why || 'the stored set is unusable') + '), so a code you ' +
            'type cannot be checked against it.') + '</p>' +
        '<p class="note">Generating a new set replaces it and fixes this. An ' +
        'administrator can also clear it from your row under ' +
        '<code>/admin/users</code>.</p>' +
        (live.enabled ? generateForm : '');
    } else {
      body =
        '<p class="sub">' +
        self.esc(status.remaining + ' of your ' + status.total +
          ' recovery codes are unused.') + '</p>' +
        '<table class="grid">' +
        '<tr><th>Saved</th><td>' +
        self.esc(status.generatedAt
          ? new Date(status.generatedAt).toISOString().slice(0, 10)
          : 'not recorded') + '</td></tr>' +
        '<tr><th>Unused</th><td>' + self.esc(String(status.remaining) + ' of ' +
          String(status.total)) + '</td></tr>' +
        '<tr><th>Last used</th><td>' +
        self.esc(status.lastUsedAt
          ? new Date(status.lastUsedAt).toISOString().slice(0, 19) + 'Z'
          : 'never') + '</td></tr>' +
        '<tr><th>Stored</th><td>' + self.esc('as a scrypt hash of each code ' +
          '— the same way your password is stored, which is why they cannot ' +
          'be shown to you again') + '</td></tr>' +
        '</table>' +
        // THE REPLACE CONTROL, WITH WHAT IT COSTS SAID BEFORE IT IS PRESSED.
        // This is the sharp edge of generating on request: there is no way to
        // see a set you already have, so the only reason to press this is that
        // you have lost it — and pressing it destroys the one you lost.
        '<p class="note"><strong>There is no way to see these ' +
        'again.</strong> Generating a new set shows you ten new codes and ' +
        '<em>replaces</em> the ones you have &mdash; every code on your ' +
        'current list stops working. Only do it if you have lost them or ' +
        'have used most of them.</p>' +
        (live.enabled ? generateForm : '') +
        (status.remaining === 0
          ? '<p class="note"><strong>Every code has been used.</strong> ' +
            'There is nothing left to fall back on until you generate a new ' +
            'set.</p>'
          : (status.remaining <= 3
              ? '<p class="note"><strong>You are nearly out.</strong> ' +
                self.esc(String(status.remaining) + ' left of ' +
                    String(status.total)) + '. They are not topped up.</p>'
              : ''));
    }

    log.debug('Leaving Portal.backupCodesCard(). present=' + status.present +
              ', advised=' + !!advised);
    return '<div class="card' + (advised && !status.present ? ' warn' : '') +
           '"><h2>Recovery codes</h2>' + body +
      (!live.enabled
        ? '<p class="note">' + self.esc('Recovery codes are turned off on ' +
            'this service (backupCodes.enabled), so no new set can be ' +
            'generated. A set already saved goes on working — a setting that ' +
            'took away the only way back into an account whose phone is lost ' +
            'would be the worst switch here.') + '</p>'
        : '') +
      '</div>';
  }

  // ===========================================================================
  // YOUR SIGNING KEY (2026-09-12): RFC 7523 SECTION 2.1, ISSUED BY THE PERSON
  // IT IS FOR.
  //
  // **THIS IS THE SECOND PAGE IN THIS PORTAL THAT HANDS SOMEBODY A CREDENTIAL
  // RATHER THAN TAKING ONE**, after `/portal/mfa`, and the third thing in this
  // service that does it at all — `/admin/pki` is the other. What it issues is
  // a key pair from this realm's Issuing CA whose whole authority is *this is
  // me*: `common/person_assertions.js` refuses an assertion signed with it that
  // names anybody else as `sub`, on the registered key and on the certificate
  // alike.
  //
  // So the bar it clears is the one the password form and the security-key
  // enrolment clear: it hands a signed-in person a credential for the account
  // they are signed in to. It is not a way to speak for somebody else, and
  // there is no field on this page that could ask for one — the identity is the
  // session's, like every other route here.
  //
  // ---------------------------------------------------------------------------
  // THE PRIVATE KEY IS SHOWN ONCE, AND THAT IS WHY `generate` RENDERS.
  //
  // Every other write on this page and on `/portal/mfa` answers 303 with a
  // message on the query string. This one cannot, for the reason
  // `generate-codes` next door cannot: a redirect has nowhere to put a
  // credential, and putting one on a query string writes it into a browser
  // history entry, this service's own access log and every proxy log between
  // here and the person.
  //
  // **AND THERE IS NO SECOND CHANCE AT IT.** The key is written to the entry
  // sealed under the key-encryption key and nothing in this service opens it
  // again — not this page, not `/admin/pki`, not `/admin-api`. That is the same
  // position the recovery codes reached from the other direction: what cannot
  // be shown again is said, on the page, at the moment it is shown. Generating
  // again is the only answer to having lost it, and it REPLACES.
  //
  // ---------------------------------------------------------------------------
  // WHAT THE PAGE DRAWS WHEN THERE IS NOTHING TO ISSUE FROM.
  //
  // A realm with no certificate authority cannot issue, and `pki.autoBuild` can
  // be off. The page says so and draws no button, rather than offering one that
  // answers an error — an operator builds the hierarchy on `/admin/pki`, which
  // is not a thing the person reading this page can do, so the sentence names
  // it as somebody else's job rather than as advice.
  // ===========================================================================
  // RFC 4517 GeneralizedTime as a person reads a date. The attribute is
  // `20270912074512Z` — which is what a directory holds and what `/admin/pki`
  // shows, because that page is read by somebody who is about to go and query
  // LDAP. This page is read by the person the certificate is for, and a date
  // with no separators in it is one they have to count digits in. An
  // unparseable value says so rather than printing eight characters of whatever
  // is there.
  private readableDate(value) {
    const { log } = this.deps;
    log.debug("Entering Portal.readableDate().");
    const found = /^(\d{4})(\d{2})(\d{2})/.exec(String(value || ''));
    log.debug("Leaving Portal.readableDate().");
    return found ? found[1] + '-' + found[2] + '-' + found[3] : 'unknown';
  }

  private signingKeyProfile(id) {
    const { log } = this.deps;
    log.debug("Entering Portal.signingKeyProfile().");
    const found = SIGNING_KEY_PROFILES.filter(function (one) {
      return one.id === id;
    })[0] || null;
    log.debug("Leaving Portal.signingKeyProfile().");
    return found;
  }

  // What a person holds for one profile, read off `recordFor()`'s record by the
  // register's own attribute table. Null where nothing is held.
  private heldProfile(held, profile) {
    const { log, personAssertions } = this.deps;
    log.debug("Entering Portal.heldProfile().");
    const names = personAssertions.KEY_PAIR_ATTRIBUTES[profile.id];
    if (!held || !names || !held[names.present]) {
      log.debug("Leaving Portal.heldProfile(). Nothing held.");
      return null;
    }
    log.debug("Leaving Portal.heldProfile().");
    return {
      handleLabel: profile.id === 'saml' ? 'Thumbprint' : 'Key',
      handle: held[names.handle] || '',
      expiresAt: held[names.expiresAt] || '',
      certificate: held[names.certificate] || '',
      issuers: profile.id === 'saml' ? held.samlEffectiveIssuers
                                     : held.effectiveIssuers
    };
  }

  // The one-time card's instructions, per profile. The JWT half is what this
  // page said before RFC 7522 joined it, word for word.
  private freshInstructions(profile, fresh, username, tokenEndpoint) {
    const self = this;
    const { log } = this.deps;
    log.debug("Entering Portal.freshInstructions().");
    const who = self.esc(String(fresh.issuer || username));
    let how;
    if (profile.id === 'saml') {
      how = '<p class="note"><strong>What to do with it.</strong> Build a ' +
        'SAML 2.0 <code>&lt;Assertion&gt;</code> whose <code>&lt;Issuer&gt;' +
        '</code> and <code>&lt;Subject&gt;&lt;NameID&gt;</code> are both ' +
        '<code>' + who + '</code>, with an <code>&lt;Audience&gt;</code> and ' +
        'a bearer <code>&lt;SubjectConfirmationData Recipient&gt;</code> of ' +
        '<code>' + self.esc(tokenEndpoint) + '</code> and a ' +
        '<code>NotOnOrAfter</code> a minute or two ahead. Sign it with an ' +
        'enveloped XML Signature using this key, base64url-encode the ' +
        'document, and present it to the token endpoint as an RFC 7522 ' +
        'section 2.1 authorization grant. This service matches the signature ' +
        'to the certificate it holds for you, thumbprint <code>' +
        self.esc(String(fresh.thumbprint || '')) + '</code>.</p>' +
        '<pre class="pem">' +
        self.esc('curl -X POST ' + tokenEndpoint + ' \\\n' +
        '  -d grant_type=' + profile.grantType + ' \\\n' +
        '  -d assertion=<the signed assertion, base64url>') + '</pre>' +
        '<p class="note"><strong>The <code>&lt;Subject&gt;</code> can only ' +
        'ever be you.</strong> An assertion signed with this key that names ' +
        'somebody else is refused — the key says who you are, and it is not ' +
        'permission to speak for anybody.</p>';
    } else {
      how = '<p class="note"><strong>What to do with it.</strong> Sign a ' +
        'JSON Web Token with it and present that to the token endpoint as an ' +
        'RFC 7523 section 2.1 authorization grant. The claims are ' +
        '<code>iss</code> and <code>sub</code> both <code>' + who +
        '</code>, an ' +
        '<code>aud</code> of <code>' + self.esc(tokenEndpoint) + '</code>, ' +
        'an <code>exp</code> a minute or two ahead, and a <code>jti</code> ' +
        'you do not reuse. The header carries <code>alg</code> <code>' +
        self.esc(String(fresh.jwsAlg || '')) +
        '</code> and <code>kid</code> <code>' +
        self.esc(String(fresh.kid || '')) + '</code>.</p>' +
        '<pre class="pem">' +
        self.esc('curl -X POST ' + tokenEndpoint + ' \\\n' +
        '  -d grant_type=' + profile.grantType + ' \\\n' +
        '  -d assertion=<the signed JWT>') + '</pre>' +
        '<p class="note"><strong>`sub` can only ever be you.</strong> An ' +
        'assertion signed with this key that names somebody else is refused ' +
        '— the key says who you are, and it is not permission to speak for ' +
        'anybody.</p>';
    }
    log.debug("Leaving Portal.freshInstructions().");
    return how;
  }

  // One profile's card: what is held, and its two controls.
  private profileCard(profile, held, csrf, issuable, offered) {
    const self = this;
    const { log } = this.deps;
    log.debug("Entering Portal.profileCard(). profile=" + profile.id);
    const mine = self.heldProfile(held, profile);
    const heading = '<h2 id="' + profile.id + '">' +
      self.esc(profile.rfc) + ': ' + self.esc(profile.title) + '</h2>';
    const status = !held
      ? ''
      : (mine
        ? '<table><tr><th>' + mine.handleLabel + '</th><td><code>' +
          self.esc(mine.handle) + '</code></td></tr>' +
          '<tr><th>You assert as</th><td>' +
          (mine.issuers || []).map(function (one) {
            return '<code>' + self.esc(one) + '</code>';
          }).join(' ') + '</td></tr>' +
          '<tr><th>Good until</th><td>' +
          self.esc(self.readableDate(mine.expiresAt)) + '</td></tr></table>' +
          (mine.certificate
            ? '<details><summary>Your certificate (public — this is the half ' +
              'anybody may hold)</summary><pre class="pem">' +
              self.esc(mine.certificate) + '</pre></details>'
            : '')
        : '<p class="sub">You have no ' + self.esc(profile.rfc) +
          ' signing key.</p>');

    const hidden = csrf + '<input type="hidden" name="purpose" value="' +
      profile.id + '">';
    let controls = '';
    if (held && issuable && offered) {
      controls =
        '<form method="post" action="' + BASE + '/signing-key">' + hidden +
        '<input type="hidden" name="action" value="generate">' +
        '<button' + (mine ? ' class="secondary"' : '') + '>' +
        (mine ? 'Generate a new ' + self.esc(profile.rfc) + ' key pair'
              : 'Generate my ' + self.esc(profile.rfc) + ' signing key') +
        '</button></form>' +
        (mine
          ? '<p class="note"><strong>Generating replaces what you ' +
            'have.</strong> The ' + self.esc(profile.rfc) + ' key you hold ' +
            'now stops being accepted the moment the new one is written, and ' +
            'anything signing with it starts being refused. Your other ' +
            'signing key, if you hold one, is untouched.</p>'
          : '<p class="note">The private half is shown once, on the page ' +
            'that comes back. Nothing here can show it to you again.</p>');
    }
    const removeForm = mine
      ? '<form method="post" action="' + BASE + '/signing-key">' + hidden +
        '<input type="hidden" name="action" value="remove"><button ' +
        'class="danger">Take my ' + self.esc(profile.rfc) + ' signing key off' +
        '</button></form><p ' +
        'class="note"><strong>This is not revocation.</strong> The ' +
        'certificate stays valid and still chains to this service&rsquo;s ' +
        'root; what changes is that this service stops accepting what the ' +
        'key signs, because the key is no longer registered against you. ' +
        'Your other signing key, your password, your security keys and your ' +
        'authenticator app are untouched — this is not a way you sign in.</p>'
      : '';
    log.debug("Leaving Portal.profileCard().");
    return '<div class="card">' + heading + status + controls + removeForm +
      '</div>';
  }

  // ===========================================================================
  // A TLS CLIENT CERTIFICATE (2026-09-13): THE THIRD CARD ON THIS PAGE.
  //
  // The two cards above hand a person a key that signs a DOCUMENT. This one
  // hands them a key and a certificate that sign a TLS HANDSHAKE: installed in
  // a browser and presented to this service's main port at `GET /tls/sign-in`,
  // it signs them in as the person it names, in the realm this page was reached
  // in. `common/tls_client_certificates.js` issues, packages, revokes and — for
  // that route and the other main-port doors — decides what counts as an
  // identity.
  //
  // **IT IS FILED HERE AND NOT ON A PAGE OF ITS OWN**, which is what rcbj asked
  // for and what the section's own description supports: the credentials on
  // your own entry that let something act as you. It shares the page's three
  // safeguards rather than growing its own — `pki.personSelfService`, the two
  // self-service rate limits (an RSA key generation costs the same CPU whatever
  // it certifies) and the page's CSRF token.
  //
  // **THE DOWNLOAD IS THE RESPONSE TO THE POST, AND NOTHING KEEPS IT.** The
  // same position the signing keys take, for their reason: a redirect has
  // nowhere to put a private key. The files go out as `data:` links with
  // `download` on them — the arrangement the console's keytab page already uses
  // — so the page that carries them also carries the install steps, and a
  // person who closes it without saving has to generate again. The PKCS#12
  // password is typed by the person, used once to build the files, and not
  // stored, logged or audited.
  // ===========================================================================

  // ---------------------------------------------------------------------------
  // WHERE A CLIENT CERTIFICATE WORKS (rewritten 2026-09-16).
  //
  // This answered two URLs — the 8443 and 9443 listeners — and both were
  // deleted. A person's certificate is presented to the MAIN port now, which
  // asks every connection for one and requires none, so the answer is one URL
  // and the route that turns it into a session.
  //
  // It is built from `base` — `helpers.baseUrlOf(req)`, which both callers
  // already hold — and not from the request. The 2026-09-16 rewrite took a
  // `req` while both callers still passed the base STRING, so `req.get` threw,
  // the catch swallowed it, and every card said `localhost`. The base also
  // honours `global.publicBaseUrl`, a trusted proxy's headers and the realm
  // prefix, none of which a bare `Host` does.
  // ---------------------------------------------------------------------------
  private tlsListenerUrls(base) {
    const { log } = this.deps;
    log.debug("Entering Portal.tlsListenerUrls().");
    const root = String(base || '').replace(/\/+$/, '');
    log.debug("Leaving Portal.tlsListenerUrls().");
    return { signIn: root + '/tls/sign-in', base: root + '/' };
  }

  // The signed-in person's `mail`, read off their own entry, for the rfc822Name
  // a certificate picker shows beside the common name. Absent is fine.
  private mailOf(session) {
    const self = this;
    const { log } = this.deps;
    log.debug("Entering Portal.mailOf().");
    const entry = self.entryFor(session);
    const attributes = (entry && entry.attributes) || {};
    const key = Object.keys(attributes).filter(function (one) {
      return one.toLowerCase() === 'mail';
    })[0];
    const values = key ? [].concat(attributes[key]) : [];
    log.debug("Leaving Portal.mailOf().");
    return values.length ? String(values[0]) : '';
  }

  private tlsClientCard(session, csrf, issuable, offered, base) {
    const self = this;
    const { log, tlsClient } = this.deps;
    log.debug("Entering Portal.tlsClientCard().");
    const username = session.user.username;
    let held = [];
    try {
      held = tlsClient.listFor(undefined, username);
    } catch (e) {
      // A process with no certificate authority holds no register to read. The
      // card says there is nothing, which is true.
      log.debug("Caught in Portal.tlsClientCard(): " + ((e && e.message) || e));
      held = [];
    }
    const report = tlsClient.report();
    const active = held.filter(function (one) {
      return one.state === 'valid';
    });
    const urls = self.tlsListenerUrls(base);
    const hidden = csrf;

    const what =
      '<p class="sub">A TLS client certificate signs you in <strong>with no ' +
      'password typed</strong>: your browser presents it when a server asks, ' +
      'and this identity provider recognises it as you. It is issued from ' +
      'this realm&rsquo;s TLS client certificate authority, names you ' +
      '(<code>CN=' + self.esc(username) + '</code> and <code>urn:sts:person:' +
      self.esc(username) + '</code>), and carries <code>clientAuth</code>. ' +
      'You download it once, as a password-protected <code>.p12</code>, and ' +
      'install it in each browser or device you want to sign in from.</p>' +
      '<p class="note">Where it works: <a ' +
      'href="' + self.esc(urls.signIn) + '">' +
      self.esc(urls.signIn) + '</a>. This service asks every connection for ' +
      'a client certificate and requires none, so your browser sends this ' +
      'one when you choose it; that page starts a sign-on session for you in ' +
      'this realm, and your other applications here then sign you in without ' +
      'asking. Your browser will first ask you to trust this service&rsquo;s ' +
      'server certificate if it does not already.</p>' +
      (report.trusted
        ? ''
        : '<p class="note"><strong>This service will not accept it at the ' +
          'moment.</strong> ' + self.esc(report.note) + ' An administrator ' +
          'can change that.</p>');

    const rows = held.length
      ? '<table class="grid"><tr><th>Name</th><th>Serial</th><th>Key</th>' +
        '<th>Good until</th><th>State</th><th></th></tr>' +
        held.map(function (one) {
          const revokeForm = one.state === 'valid'
            ? '<form method="post" action="' + BASE + '/signing-key">' +
              hidden +
              '<input type="hidden" name="action" value="revoke-tls-client">' +
              '<input type="hidden" name="serial" value="' +
              self.esc(one.serialHex) + '">' +
              '<select name="reason" aria-label="Why"><option ' +
              'value="cessationOfOperation">I no longer use it</option>' +
              '<option value="keyCompromise">Somebody else may have the key' +
              '</option></select> <button class="danger">Revoke</button></form>'
            : (one.revokedAt ? '<span class="note">revoked ' +
              self.esc(String(one.revokedAt).slice(0, 10)) + '</span>' : '');
          return '<tr><td>' + self.esc(one.label) + '</td><td><code>' +
            self.esc(String(one.serialHex).slice(-16)) + '</code></td><td>' +
            self.esc(one.keyAlg) + '</td><td>' +
            self.esc(String(one.notAfter).slice(0, 10)) + '</td><td><span ' +
            'class="state-' + self.esc(one.state) + '">' + self.esc(one.state) +
            (one.reason && one.state === 'revoked'
              ? ' (' + self.esc(one.reason) + ')' : '') +
            '</span></td><td>' + revokeForm + '</td></tr>';
        }).join('') + '</table>'
      : '<p class="sub">You have no TLS client certificate.</p>';

    let controls = '';
    if (!issuable) {
      controls = '';
    } else if (!offered) {
      controls = '';
    } else if (active.length >= report.maxPerPerson) {
      controls = '<p class="note"><strong>You hold ' + active.length + ' ' +
        'valid TLS client certificates, which is the most this service ' +
        'issues to one person.</strong> Revoke one you no longer use to make ' +
        'room.</p>';
    } else {
      controls =
        '<form method="post" action="' + BASE + '/signing-key">' + hidden +
        '<input type="hidden" name="action" value="generate-tls-client">' +
        '<label for="tls-label">Name it after the browser or device ' +
        '(optional)</label><input type="text" id="tls-label" name="label" ' +
        'maxlength="40" placeholder="work laptop">' +
        '<label for="tls-key-alg">Key</label><select id="tls-key-alg" ' +
        'name="key_alg">' + tlsClient.KEY_ALGS.map(function (one) {
          return '<option value="' + self.esc(one) + '"' +
            (one === tlsClient.DEFAULT_KEY_ALG ? ' selected' : '') + '>' +
            self.esc(one === 'rsa-2048' ? 'RSA 2048 (works everywhere)'
              : one === 'rsa-3072' ? 'RSA 3072'
              : one === 'ec-p256' ? 'ECDSA P-256' : 'ECDSA P-384') +
            '</option>';
        }).join('') + '</select>' +
        '<label for="tls-p12-password">A password for the downloaded file' +
        '</label><input type="password" id="tls-p12-password" ' +
        'name="p12_password" minlength="' + tlsClient.PKCS12_PASSWORD_MIN +
        '" autocomplete="new-password" required>' +
        '<label for="tls-p12-confirm">The same password again</label>' +
        '<input type="password" id="tls-p12-confirm" name="p12_confirm" ' +
        'minlength="' + tlsClient.PKCS12_PASSWORD_MIN + '" ' +
        'autocomplete="new-password" required>' +
        '<p class="note">This password protects the private key inside the ' +
        'file while it sits on your disk; your browser asks for it once, ' +
        'when you import the file. It is not your account password, and this ' +
        'service does not keep it.</p><button>Generate and download my TLS ' +
        'client certificate</button></form>';
    }
    log.debug("Leaving Portal.tlsClientCard(). " + held.length + " held.");
    return '<div class="card"><h2 id="tls-client">TLS client certificate</h2>' +
      what + rows + controls +
      (active.length
        ? '<p class="note"><strong>Revoking is revocation.</strong> The ' +
          'certificate goes on this realm&rsquo;s certificate revocation ' +
          'list, its OCSP responder answers <code>revoked</code>, and the ' +
          'TLS listeners refuse it from then on. It cannot be undone; ' +
          'generate a new one instead.</p>'
        : '') + '</div>';
  }

  // The one-time card: the three files, and what to do with them.
  private tlsClientFreshCard(fresh, base) {
    const self = this;
    const { log } = this.deps;
    log.debug("Entering Portal.tlsClientFreshCard().");
    const files = fresh.files;
    const issued = fresh.issued;
    const urls = self.tlsListenerUrls(base);
    const dataUri = function (mime, base64) {
      log.debug("Entering dataUri().");
      log.debug("Leaving dataUri().");
      return 'data:' + mime + ';base64,' + base64;
    };
    const b64 = function (text) {
      log.debug("Entering b64().");
      log.debug("Leaving b64().");
      return Buffer.from(String(text), 'utf8').toString('base64');
    };
    const p12 = files.pkcs12.name;
    const key = files.key.name;
    const chain = files.chain.name;
    const step = function (title, items) {
      log.debug("Entering step().");
      log.debug("Leaving step().");
      return '<details><summary>' + title + '</summary><ol class="steps">' +
        items.map(function (one) { return '<li>' + one + '</li>'; }).join('') +
        '</ol></details>';
    };
    const html = '<div class="card"><h2>Save your TLS client certificate</h2>' +
      '<p class="sub"><strong>This is the only time these files can be ' +
      'downloaded.</strong> The private key is not kept by this service — ' +
      'not on this page, not by an administrator. If you lose the files, ' +
      'revoke this certificate below and generate a new one.</p>' +
      '<p><a class="dl" download="' + self.esc(p12) + '" href="' +
      self.esc(dataUri(files.pkcs12.mime, files.pkcs12.base64)) +
      '">Download ' + self.esc(p12) +
      '</a><a class="dl secondary" download="' + self.esc(key) +
      '" href="' + self.esc(dataUri(files.key.mime, b64(files.key.text))) +
      '">Download ' + self.esc(key) + '</a><a class="dl secondary" download="' +
      self.esc(chain) + '" href="' +
      self.esc(dataUri(files.chain.mime, b64(files.chain.text))) +
      '">Download ' + self.esc(chain) + '</a></p>' +
      '<table><tr><th>Issued to</th><td><code>' + self.esc(issued.subject) +
      '</code></td></tr><tr><th>Serial</th><td><code>' +
      self.esc(issued.serialHex) + '</code></td></tr><tr><th>Key</th><td>' +
      self.esc(issued.keyAlg) + '</td></tr><tr><th>Good until</th><td>' +
      self.esc(String(issued.notAfter).slice(0, 10)) + '</td></tr></table>' +
      '<p class="note">The <code>.p12</code> holds the private key, your ' +
      'certificate and the two certificate authorities above it, protected ' +
      'by the password you just chose. The <code>-key.pem</code> is the same ' +
      'key encrypted under the same password, and <code>-chain.pem</code> is ' +
      'the certificates alone — both for command-line tools.</p>' +
      '<h3>Install it</h3>' +

      step('Chrome or Edge on Windows', [
        'Open the downloaded <code>' + self.esc(p12) + '</code>. The ' +
        'Certificate Import Wizard starts.',
        'Choose <em>Current User</em>, keep the file, and type the file ' +
        'password.',
        'Let Windows choose the store automatically, and finish.',
        'Restart the browser.']) +
      step('Chrome, Edge or Safari on macOS', [
        'Open the downloaded <code>' + self.esc(p12) + '</code>. Keychain ' +
        'Access offers to add it to the <em>login</em> keychain.',
        'Type the file password.',
        'Chrome, Edge and Safari all use that keychain.']) +
      step('Firefox (any operating system)', [
        'Open <em>Settings → Privacy &amp; Security</em> and scroll to ' +
        '<em>Certificates</em>.',
        'Press <em>View Certificates…</em>, open the <em>Your ' +
        'Certificates</em> tab and press <em>Import…</em>.',
        'Choose <code>' + self.esc(p12) + '</code> and type the file ' +
                                          'password.']) +
      step('Chrome or Edge on Linux', [
        'Open <code>chrome://certificate-manager</code> (or ' +
        '<code>edge://certificate-manager</code>) and choose <em>Your ' +
        'certificates</em>.',
        'Press <em>Import</em>, choose <code>' + self.esc(p12) + '</code> ' +
        'and type the file password.',
        'On an older browser: <code>pk12util -d sql:$HOME/.pki/nssdb -i ' +
        self.esc(p12) + '</code>.']) +
      step('curl or openssl', [
        '<code>curl --cert ' + self.esc(chain) + ' --key ' + self.esc(key) +
        ' --pass &lt;file password&gt; ' + self.esc(urls.signIn) + '</code>',
        'If a macOS release older than your browser refuses the ' +
        '<code>.p12</code> with a message about the password, rebuild it ' +
        'with the older algorithms it expects: <code>openssl pkcs12 -export ' +
        '-legacy -inkey ' + self.esc(key) + ' ' +
                                            '-in ' + self.esc(chain) + ' ' +
        '-out legacy.p12</code>.']) +
      '<h3>Use it</h3><p>Open <a href="' + self.esc(urls.signIn) + '">' +
      self.esc(urls.signIn) + '</a> in the browser you installed it in and ' +
      'choose this certificate when asked. What comes back says whether it ' +
      'signed you in and who as; then come back to <a href="' + BASE +
      '">your ' +
      'account</a>, which will not ask you to sign in again.</p></div>';
    log.debug("Leaving Portal.tlsClientFreshCard().");
    return html;
  }

  // `fresh`, when it is set, carries `purpose`: which profile the key it holds
  // was just issued for, so the one-time card tells somebody what to do with
  // IT. A `fresh.kind` of `tls-client` is the third card's one-time answer
  // instead.
  private signingKeyPage(session, message, error, fresh, base) {
    const self = this;
    const { config, log, personAssertions, pki, websecurity } = this.deps;
    log.debug("Entering Portal.signingKeyPage().");
    const username = session.user.username;
    log.debug('Entering Portal.signingKeyPage(). username=' + username);
    const csrf = websecurity.field(session.id);
    const held = personAssertions.recordFor(username);
    const offered = config.value('pki.personSelfService') !== false;
    const issuable = pki.hasChain();
    const tokenEndpoint = String(base || '') + '/oauth2/token';

    // -----------------------------------------------------------------------
    // THE CARD THAT ONLY EXISTS FOR ONE RESPONSE: the key itself.
    // -----------------------------------------------------------------------
    const tlsFresh = !!(fresh && fresh.kind === 'tls-client');
    const freshProfile = fresh && !tlsFresh
      ? (self.signingKeyProfile(fresh.purpose) || SIGNING_KEY_PROFILES[0])
      : null;
    const freshCard = tlsFresh ? self.tlsClientFreshCard(fresh, base)
      : (fresh && fresh.privateKeyPem)
      ? '<div class="card"><h2>Save this ' + self.esc(freshProfile.rfc) +
        ' private key</h2><p ' +
        'class="sub"><strong>This is the only time it will be ' +
        'shown.</strong> It is stored on your entry encrypted, and nothing ' +
        'in this service — not this page, not an administrator — can print ' +
        'it again. Copy it now; if you lose it, generate a new key pair, ' +
        'which replaces this one.</p><pre ' +
        'class="pem">' + self.esc(String(fresh.privateKeyPem)) + '</pre>' +
        self.freshInstructions(freshProfile, fresh, username, tokenEndpoint) +
        '</div>'
      : '';

    // -----------------------------------------------------------------------
    // WHAT IT IS FOR. Drawn whether or not one is held, because this is the
    // page somebody arrives at not knowing what a signing key would be for.
    // -----------------------------------------------------------------------
    const what =
      '<p class="sub">A signing key lets something act as you ' +
      '<strong>without a browser</strong>: a script or a service signs a ' +
      'short-lived document with it and this identity provider hands back an ' +
      'access token for you. No password is typed and no sign-in screen is ' +
      'drawn — the signature is the whole of it.</p><p class="note">There ' +
      'are two kinds, one per document format, and they are <strong>separate ' +
      'key pairs</strong>: RFC 7523&rsquo;s <em>JWT bearer authorization ' +
      'grant</em> signs a JSON Web Token, and RFC 7522&rsquo;s <em>SAML 2.0 ' +
      'bearer authorization grant</em> signs a SAML assertion. A key issued ' +
      'for one is refused by the other. This service issues each key pair ' +
      'from its own certificate authority, keeps the public half on your ' +
      'entry to check signatures with, and gives you the private half ' +
      'once.</p><p class="note">The third card is a different kind of key: a ' +
      '<a href="#tls-client">TLS client certificate</a>, which signs you in ' +
      'from a browser rather than letting a script act as you.</p>';

    // -----------------------------------------------------------------------
    // WHAT APPLIES TO BOTH: no entry, no certificate authority, or the feature
    // turned off. Said once rather than once per profile.
    // -----------------------------------------------------------------------
    let shared = '';
    if (!held) {
      shared = '<p class="sub">This service holds no entry for you, so there ' +
        'is nowhere to put a key pair.</p>';
    } else if (!issuable) {
      shared = '<p class="note"><strong>Nothing can be issued here at the ' +
        'moment.</strong> This service has no certificate authority in this ' +
        'realm, and building one is an administrator&rsquo;s job rather than ' +
        'something this page can do.</p>';
    } else if (!offered) {
      shared = '<p class="note"><strong>This service does not let people ' +
        'issue their own signing keys</strong> ' +
        '(<code>pki.personSelfService</code> is off). An administrator can ' +
        'still issue one to you.' +
        ((held.hasKeyPair || held.hasSamlKeyPair)
          ? ' The keys you already hold are unaffected and go on working.'
          : '') + '</p>';
    }

    const html = self.shell(BASE + '/signing-key', session, message, error,
      freshCard +
      '<div class="card">' + what + shared + '</div>' +
      SIGNING_KEY_PROFILES.map(function (profile) {
        return self.profileCard(profile, held, csrf, issuable, offered);
      }).join('') +
      self.tlsClientCard(session, csrf, issuable, offered, base));
    log.debug('Leaving Portal.signingKeyPage(). ' +
              (held && held.hasKeyPair ? 'A JWT key pair. ' : 'No JWT key ' +
               'pair. ') +
              (held && held.hasSamlKeyPair ? 'A SAML key pair.'
                                           : 'No SAML key pair.'));
    return html;
  }

  // ---------------------------------------------------------------------------
  // THE PENDING ENROLMENT, RE-RENDERED FROM WHAT IS HELD.
  //
  // The QR code and the URI are DERIVED from the secret every time this page is
  // drawn rather than being kept beside it, so there is one copy of the secret
  // in memory and no second representation of it to go stale — a page redrawn
  // after a mistyped code shows the same account, which is what stops somebody
  // having to scan again for a typo.
  // ---------------------------------------------------------------------------
  private async pendingEnrolmentFor(username, base) {
    const { credentials, errorCodes, log, totp } = this.deps;
    log.debug('Entering Portal.pendingEnrolmentFor(). username=' + username);
    const held = credentials.pendingTotpFor(username);
    if (!held) {
      log.debug('Leaving Portal.pendingEnrolmentFor(). Nothing pending.');
      return null;
    }
    const issuer = totp.issuerFor(base);
    const uri = totp.otpauthUri({ issuer: issuer, account: username,
                                  secret: held.secret,
                                  algorithm: held.algorithm,
                                  digits: held.digits, period: held.period });
    let qr = '';
    try {
      qr = await totp.qrSvgDataUri(uri);
    } catch (e) {
      // NOT fatal, and the page says so by showing the typed secret alone. A QR
      // renderer that fails must not cost somebody the ability to set up a
      // second factor, because the transcribable form is the whole credential.
      log.error(errorCodes.tag('STS-PORTAL-0016') +
                'portal: the QR code could not be drawn (' + e.message +
                '), so the enrolment is offered by hand only.');
    }
    log.debug('Leaving Portal.pendingEnrolmentFor(). Rendered.');
    return { ok: true, secret: held.secret, grouped: totp.grouped(held.secret),
             issuer: issuer, uri: uri, qr: qr,
             algorithm: held.algorithm, digits: held.digits,
             period: held.period };
  }

  private scanLimit() {
    const { config, log } = this.deps;
    log.debug("Entering Portal.scanLimit().");
    const n = Number(config.value('portal.applicationScanLimit'));
    log.debug("Leaving Portal.scanLimit().");
    return isFinite(n) && n > 0 ? Math.floor(n) : SCAN_LIMIT;
  }

  // Which of the five this entry is a sign-in destination in. DECLARED and
  // OBSERVED both count, and the union is deliberate: an entry an operator
  // created and ticked SAML 2.0 on has never been seen, and one that has been
  // signing people in for a month may never have been declared anything. Either
  // is an answer to "could I sign in to this".
  private signInFamiliesOf(row) {
    const { log } = this.deps;
    log.debug("Entering Portal.signInFamiliesOf().");
    const declared = row.allowedProtocols || [];
    const recorded = row.recordedProtocols || [];
    log.debug("Leaving Portal.signInFamiliesOf().");
    return SIGN_IN_FAMILIES.filter(function (family) {
      return declared.indexOf(family.protocol) >= 0 ||
             recorded.indexOf(family.protocol) >= 0;
    });
  }

  // ---------------------------------------------------------------------------
  // THE QUESTION, ASKED ONCE PER APPLICATION PER DISTINCT ISSUANCE KIND.
  //
  // Per KIND rather than per family, because the gate's vocabulary is the kind:
  // SAML 2.0 and SAML 1.1 both end in `issue-saml-assertion`, so asking twice
  // would be asking one question twice and paying for it. Per kind rather than
  // once per application, because `kind` becomes the XACML `action-id` of the
  // request — a policy that says something different about an ID Token from
  // what it says about a SAML assertion is a policy somebody may write, and a
  // page that asked about one and reported the other would be wrong in exactly
  // the case the person cared about.
  //
  // An application is listed if ANY of its kinds is permitted, and the row says
  // which — "permitted for a SAML 2.0 assertion, refused for an access token"
  // is the true answer and is drawn as such.
  // ---------------------------------------------------------------------------
  private applicationsFor(username) {
    const self = this;
    const { applications, gate, log } = this.deps;
    log.debug('Entering Portal.applicationsFor(). username=' + username);
    const all = applications.list();
    const limit = self.scanLimit();
    const scanned = all.slice(0, limit);
    const rows = [];
    let refused = 0;
    let notSignIn = 0;

    scanned.forEach(function (one) {
      const families = self.signInFamiliesOf(one);
      if (!families.length) {
        notSignIn++;
        return;
      }
      const answers = {};
      families.forEach(function (family) {
        if (Object.prototype.hasOwnProperty.call(answers, family.kind)) {
          return;
        }
        answers[family.kind] = gate.check({
          application: one.identifier,
          kind: family.kind,
          subject: { kind: 'user', name: username, authenticated: true },
          // THE DRY RUN. See the header above: nothing is being issued, so a
          // refusal here is not an event and is not a decision this service
          // acted on.
          preview: true
        });
      });
      const permitted = families.filter(function (family) {
        return answers[family.kind].allowed;
      });
      if (!permitted.length) {
        refused++;
        return;
      }
      rows.push({
        identifier: one.identifier,
        name: one.name || one.identifier,
        // WHERE TO GO, or '' — and the second is a state this page draws rather
        // than hides. `applications.homePageOf()` is the one reader of
        // `appHomePageUrl` and the one place the http/https rule is applied; a
        // test of its own here would be a second opinion about what may become
        // a link. An entry with no home page is drawn with its name greyed out
        // and the foot of the page says who can fix that.
        homePage: applications.homePageOf(one),
        // The first description on the entry, if it carries one. An application
        // registered by a client has none; one an operator created usually
        // does.
        description: (one.descriptions || [])[0] || '',
        families: permitted.map(function (family) {
          const detail = applications.protocolRow(family.protocol);
          return detail ? detail.label : family.protocol;
        }),
        ways: permitted.map(function (family) { return family.how; })
          .filter(function (how, at, list) {
            return list.indexOf(how) === at;
          }),
        // The families the policy did NOT permit, so a row that is half open
        // says so rather than reading as fully open. This names no application
        // the person cannot reach — it is about one they can.
        withheld: families.filter(function (family) {
          return !answers[family.kind].allowed;
        }).map(function (family) {
          const detail = applications.protocolRow(family.protocol);
          return detail ? detail.label : family.protocol;
        })
      });
    });

    // ALPHABETICAL, and not the registry's own order. `applications.list()`
    // sorts by when each was last seen, which is the right order for an
    // operator watching traffic and the wrong one for a person looking for an
    // application by name: it reshuffles between page loads for reasons that
    // have nothing to do with the reader.
    rows.sort(function (a, b) {
      return a.name.toLowerCase().localeCompare(b.name.toLowerCase()) ||
             a.identifier.localeCompare(b.identifier);
    });

    log.debug('Leaving Portal.applicationsFor(). ' + rows.length +
              ' permitted, ' + refused + ' refused, ' + notSignIn +
              ' not sign-in destinations.');
    return { rows: rows, refused: refused, notSignIn: notSignIn,
             scanned: scanned.length, total: all.length,
             truncated: all.length > scanned.length, limit: limit };
  }

  // ---------------------------------------------------------------------------
  // THE APPLICATION'S NAME, AS A LINK OR AS A GREYED-OUT LABEL.
  //
  // Added 2026-09-10. This page listed the applications a person may be signed
  // in to and gave them no way to reach any of them: a name and a client_id are
  // not somewhere you can go, and "where is Acme Expenses" is the first
  // question somebody reading this list has.
  //
  // **THE LINK IS THE ENTRY'S DECLARED HOME PAGE AND IS NEVER A GUESS.** The
  // registry grew `appHomePageUrl` for this, and `common/applications.js`'s row
  // for it argues at length why it is stated rather than computed from the
  // redirect URIs already on the entry — a redirect URI is a CALLBACK, and its
  // origin is a guess that is wrong for every application served under a path.
  // A page whose links are right often enough that nobody checks them is worse
  // than a page with no links.
  //
  // **AN ENTRY WITH NO HOME PAGE IS DRAWN GREYED OUT RATHER THAN LEFT LOOKING
  // LIVE**, which is the state this function exists to make visible. It is not
  // an error and it is not this person's to fix — most entries in this registry
  // were created by a protocol endpoint recognising an identifier, and nothing
  // in any of those requests says where the application lives. So the name is
  // still the name, it is simply not a way in, and the foot of the page says
  // who can make it one. `title` carries that sentence for a reader who hovers,
  // because a grey name with no explanation reads as something broken.
  //
  // **IT IS STILL NOT A LAUNCH BUTTON**, and the card below the table keeps
  // that argument: this service implements identity-provider-initiated sign-on
  // in none of the four browser profiles, so a link that STARTED a sign-in
  // would have to invent a request the application never asked for. This link
  // goes to the application's own front door and hands it nothing — which is
  // where a sign-in starts, and is exactly what a person would type themselves.
  // ---------------------------------------------------------------------------
  private linkedName(row) {
    const self = this;
    const { log } = this.deps;
    log.debug("Entering Portal.linkedName().");
    if (!row.homePage) {
      log.debug("Leaving Portal.linkedName().");
      return '<span class="unlinked" title="This application has not told ' +
        'this identity provider where it lives, so there is nothing to link ' +
        'to. Whoever administers this service can set its home page on the ' +
        'application\'s entry.">' + self.esc(row.name) + '</span>';
    }
    log.debug("Leaving Portal.linkedName().");
    // `rel="noopener"` on a link out of a page somebody is signed in to. There
    // is no `target` — this service opens nothing in a new window anywhere — so
    // the `noopener` is belt over braces; `Referrer-Policy: no-referrer` is
    // already set on every response by `common/app.js`, so nothing about this
    // page is told to the application either.
    return '<a class="home" rel="noopener" ' +
           'href="' + self.esc(row.homePage) + '">' +
      self.esc(row.name) + '</a>';
  }

  private applicationsPage(session, message, error, wanted) {
    const self = this;
    const { log } = this.deps;
    log.debug('Entering Portal.applicationsPage().');
    const found = self.applicationsFor(session.user.username);
    const pages = Math.max(1, Math.ceil(found.rows.length / PER_PAGE));
    const at = Math.min(Math.max(1, wanted || 1), pages);
    const shown = found.rows.slice((at - 1) * PER_PAGE, at * PER_PAGE);

    const table = shown.length
      ? '<table class="grid"><tr><th>Application</th><th>Sign-in</th>' +
        '<th>You would be issued</th></tr>' +
        shown.map(function (row) {
          return '<tr><td><strong>' + self.linkedName(row) + '</strong>' +
            '<span class="ident"><code>' + self.esc(row.identifier) +
            '</code></span>' +
            (row.description
              ? '<span ' +
                'class="ident">' + self.esc(row.description) + '</span>' : '') +
            '</td><td>' +
            row.families.map(function (label) {
              return '<span class="tag">' + self.esc(label) + '</span>';
            }).join('') +
            (row.withheld.length
              ? '<span class="ident">not ' + self.esc(row.withheld.join(', ')) +
                ' — the policy permits the other' +
                (row.families.length === 1 ? '' : 's') + '</span>'
              : '') +
            '</td><td>' + self.esc(row.ways.join(', ')) + '</td></tr>';
        }).join('') + '</table>'
      : '<p class="note">There is nothing here yet. Either this service has ' +
        'no applications registered that sign people in, or the issuance ' +
        'policy does not permit you any of them.</p>';

    const paging = pages > 1
      ? '<p class="pagenav">' +
        (at > 1
          ? '<a href="' + self.esc(BASE + '/applications?page=' + (at - 1)) +
            '">Previous</a>'
          : '<span class="off">Previous</span>') +
        '<span class="here">Page ' + self.esc(String(at)) + ' of ' +
        self.esc(String(pages)) + '</span>' +
        (at < pages
          ? '<a href="' + self.esc(BASE + '/applications?page=' + (at + 1)) +
            '">Next</a>'
          : '<span class="off">Next</span>') +
        '</p>'
      : '';

    const html = self.shell(BASE + '/applications', session, message, error,
      '<div class="card"><p class="sub">Where this identity provider will ' +
      'sign you in. Each row was decided by the SAME policy the token ' +
      'endpoint, both SAML profiles and WS-Federation ask before they issue ' +
      'anything — so this page and those endpoints cannot disagree.</p>' +
      table + paging +
      '</div>' +

      '<div class="card">' +
      '<h2>What is not on this list</h2>' +
      '<table>' +
      '<tr><th>Not permitted to you</th><td>' +
        self.esc(String(found.refused)) +
        (found.refused === 1 ? ' application' : ' applications') +
        '. They are counted rather than named: which applications exist here ' +
        'is not a question this page answers. Whoever administers this ' +
        'service decides, by giving your account a role the application ' +
        'requires.</td></tr><tr><th>Not sign-in destinations</th><td>' +
        self.esc(String(found.notSignIn)) +
        (found.notSignIn === 1 ? ' entry' : ' entries') +
        '. A registered application is not necessarily somewhere a person ' +
        'signs in — a Shared Signals receiver, a SCIM provisioning client, ' +
        'an LDAP binder, a SPIFFE workload or a WS-Trust relying party is an ' +
        'application this service knows and not a door you walk ' +
        'through.</td></tr>' +
      (found.truncated
        ? '<tr><th>Not looked at</th><td>' +
          self.esc(String(found.total - found.scanned)) + ' of ' +
          self.esc(String(found.total)) + ' entries. This page evaluates the ' +
          'issuance policy for each application it lists and stops at ' +
          self.esc(String(found.limit)) + ' (portal.applicationScanLimit), ' +
          'because that work happens on the one ' +
          'thread answering every socket this service holds.</td></tr>'
        : '') +
      '</table><p class="note">A name in blue links to the application\'s ' +
      'own home page and hands it nothing — it is where you would go ' +
      'yourself, and a sign-in starts there. A name in grey means this ' +
      'identity provider has not been told where that application lives; ' +
      'whoever administers this service can set a home page on its entry, ' +
      'and until then there is nothing to link to. Neither is a button that ' +
      'starts a sign-in for you: this service implements no ' +
      'identity-provider-initiated sign-on in any of the four browser ' +
      'profiles — <code>/saml2</code> says so on its own page — so a link ' +
      'that began one would have to invent a request the application never ' +
      'asked for and is not expecting.</p></div>');
    log.debug('Leaving Portal.applicationsPage(). Page ' + at + ' ' +
      'of ' + pages + '.');
    return html;
  }

  // What a person is, for the purposes of "is this event about me". Three names
  // and no more: the username they signed in as, the `sub` the ID Token
  // carried, and the address on their entry if there is one. Everything else
  // this service could put in a subject is derived from one of those by
  // `ssf_subjects.js`'s `subjectForUser()`, which is where the derivations live
  // and where `isAbout()` reads them back.
  private personOf(session) {
    const { log } = this.deps;
    log.debug('Entering Portal.personOf().');
    const out = {
      username: session.user.username,
      sub: session.user.sub || '',
      mail: session.user.email || ''
    };
    log.debug('Leaving Portal.personOf(). ' + out.username);
    return out;
  }

  // ---------------------------------------------------------------------------
  // WHETHER SECURITY EVENTS ABOUT THIS ACCOUNT ARE SHARED (#146, RISC 1.0
  // section 2.8), which the specification makes the ACCOUNT HOLDER's choice.
  // Opting out is not immediate: it enters opt-out-initiated, receivers keep
  // being told everything, and after risc.optOutDelayHours it becomes
  // effective — the delay exists so that somebody who has just taken an
  // account over cannot silence the events that would report them. Only the
  // move the state diagram allows from where the account is gets a button.
  // ---------------------------------------------------------------------------
  private participationCard(session): string {
    const self = this;
    const { log, risc, config, websecurity } = this.deps;
    log.debug('Entering Portal.participationCard().');
    if (!risc.enabled()) {
      log.debug('Leaving Portal.participationCard(). RISC is off.');
      return '';
    }
    const username = session.user.username;
    const now = risc.optOutOf(username);
    const hours = Number(config.value('risc.optOutDelayHours'));
    const said = now.state === 'opt-in'
      ? 'Security events about your account <strong>are shared</strong> ' +
        'with the applications that receive them.'
      : now.state === 'opt-out-initiated'
        ? 'You asked to <strong>stop sharing</strong> security events ' +
          (now.since ? 'on ' + self.esc(now.since) + ' ' : '') +
          'and it takes effect ' + self.esc(String(hours)) + ' hour(s) ' +
          'after you asked. Until then they are still shared, and you can ' +
          'cancel.'
        : 'Security events about your account are <strong>not ' +
          'shared</strong>, apart from the notice that you opted out.';
    const labels = { optOutInitiated: 'Stop sharing security events',
                     optOutCancelled: 'Cancel: keep sharing them',
                     optIn: 'Share security events again' };
    const buttons = now.moves.map(function (move) {
      return '<form method="post" action="' + self.esc(BASE + '/signals') +
        '">' + websecurity.field(session.id) +
        '<input type="hidden" name="move" value="' + self.esc(move) + '">' +
        '<button' + (move === 'optOutInitiated' ? ' class="danger"' : '') +
        '>' + self.esc(labels[move]) + '</button></form>';
    }).join('');
    log.debug('Leaving Portal.participationCard(). ' + now.state);
    return '<div class="card"><h2>Sharing security events about your ' +
      'account</h2><p>' + said + '</p>' + buttons +
      '<p class="note">These are OpenID RISC events: an account disabled, a ' +
      'password that must be changed, a contact detail changed. Applications ' +
      'you use receive them to protect your account there. Stopping them is ' +
      'your choice (RISC section 2.8), and it waits ' +
      self.esc(String(hours)) + ' hour(s) so that somebody who has taken ' +
      'your account over cannot silence them at once.</p></div>';
  }

  private signalsPage(session, message, error, wanted) {
    const self = this;
    const { log, signals } = this.deps;
    log.debug('Entering Portal.signalsPage().');
    const view = signals.view(signals.PORTAL,
                              { person: self.personOf(session) });
    /** @type {any} */
    const st: any = view.status || {};
    const rows = view.received;
    const pages = Math.max(1, Math.ceil(rows.length / PER_PAGE));
    const at = Math.min(Math.max(1, wanted || 1), pages);
    const shown = rows.slice((at - 1) * PER_PAGE, at * PER_PAGE);

    // WHY THERE MIGHT BE NOTHING, ABOVE THE LIST. `status()` works out which of
    // the five causes apply. The wording here is a PERSON's rather than an
    // operator's — the console's copy of this names the settings, and somebody
    // reading their own account page cannot change any of them — so this says
    // what it means for them and points at who can.
    const why = st.why && st.why.length
      ? '<div class="err"><p>This portal is not currently being told about ' +
        'everything that happens to your account, so this list may be ' +
        'incomplete. An administrator can see why on ' +
        '<a href="/admin/signals">the console\'s copy of this ' +
        'page</a>.</p></div>'
      : '';

    const list = shown.length
      ? '<table class="grid"><tr><th>When</th><th>What happened</th>' +
        '<th>Detail</th></tr>' +
        shown.map(function (row) {
          return '<tr><td>' + self.esc(row.at) + '</td>' +
            '<td><strong>' + self.esc(row.name) + '</strong>' +
            '<span class="ident"><span ' +
            'class="tag">' + self.esc(row.vocabulary) +
            '</span> ' + self.esc(row.types[0] || '') + '</span></td>' +
            '<td>' +
            (Object.keys(row.payload).length
              ? '<details><summary>' +
                self.esc(String(Object.keys(row.payload).length) + ' ' +
                  'detail(s)') +
                '</summary><pre>' +
                self.esc(JSON.stringify(row.payload, null, 2)) +
                '</pre></details>'
              : '<span class="ident">nothing beyond the event itself</span>') +
            '<span class="ident">' +
            (row.verified
              ? 'signed by this identity provider and verified'
              : 'NOT VERIFIED — ' + self.esc(row.verificationNote)) +
            '</span></td></tr>';
        }).join('') + '</table>'
      : '<p class="note">Nothing has been reported about your account' +
        (st.held ? ' yet' : ' yet') + '. This list fills when this identity ' +
        'provider tells this portal that something happened to one of your ' +
        'sessions or to your account &mdash; a sign-in, a sign-out, a ' +
        'session revoked, an account disabled or enabled, an identifier ' +
        'changed.</p>';

    const paging = pages > 1
      ? '<p class="pagenav">' +
        (at > 1
          ? '<a href="' + self.esc(BASE + '/signals?page=' + (at - 1)) +
            '">Previous</a>'
          : '<span class="off">Previous</span>') +
        '<span class="here">Page ' + self.esc(String(at)) + ' of ' +
        self.esc(String(pages)) + '</span>' +
        (at < pages
          ? '<a ' +
            'href="' + self.esc(BASE + '/signals?page=' + (at + 1)) +
            '">Next</a>'
          : '<span class="off">Next</span>') +
        '</p>'
      : '';

    const html = self.shell(BASE + '/signals', session, message, error,
      self.participationCard(session) +
      '<div class="card">' +
      '<h2>What has been reported about your account</h2>' +
      '<p class="sub">This portal is a registered receiver of this identity ' +
      'provider\'s security event feed. When something happens to one of ' +
      'your sessions or to your account, a signed notice is delivered here ' +
      '&mdash; and this is every one of them that was about you.</p>' +
      why +
      list +
      paging +
      '</div><div class="card"><h2>What this list is, and what it is ' +
      'not</h2><p class="note"><strong>Only the notices about you are ' +
      'here.</strong> This portal is told about everybody it serves, and ' +
      'what you are shown is narrowed to the notices whose subject is you. ' +
      'Where a notice names somebody in a way this service cannot match to ' +
      'an account &mdash; a phone number, for instance &mdash; it is left ' +
      'out rather than guessed at, so it is possible for something about you ' +
      'to be missing from this list. It is never possible for something ' +
      'about somebody else to be on it.</p><p class="note"><strong>This list ' +
      'is a record and not a control</strong> (the one control on this page ' +
      'is whether events are shared at all, above). Nothing in it can be ' +
      'edited or removed, including by you: a list of what was said about ' +
      'your account would be worth nothing if the account\'s owner could ' +
      'empty it. To end ' +
      'a session, use <a href="/logout">sign out of everything</a>; to ' +
      'change a credential, use the pages in <em>How you sign in</em>.</p><p ' +
      'class="note">The notices are OpenID CAEP (what happened to a ' +
      '<em>session</em>) and OpenID RISC (what happened to an ' +
      '<em>account</em>) events, carried over the Shared Signals Framework ' +
      'and signed by this identity provider. Each one was verified against ' +
      'its signature before it was recorded here; a notice that did not ' +
      'verify is shown saying so rather than hidden.</p></div>');
    log.debug('Leaving Portal.signalsPage(). ' + shown.length + ' ' +
      'of ' + rows.length +
              ' shown.');
    return html;
  }

  // ---------------------------------------------------------------------------
  // THE ONE RESPONSE IN THIS PORTAL THAT RELAXES THE CONTENT SECURITY POLICY.
  //
  // `app.js` sets `script-src 'none'` on everything and `portal/CLAUDE.md` says
  // every page of this portal is covered by it. That is now *every page but
  // this one*, and the exception is the smallest that works: `'self'`, naming a
  // resource, never `'unsafe-inline'`.
  //
  // **THROUGH `app.contentSecurityPolicy()` AND NOT A HAND-WRITTEN HEADER**,
  // which is the rule the root CLAUDE.md states and the reason it exists: that
  // builder re-adds `frame-ancestors` and `base-uri` whatever the caller asks
  // for, and a relaxation that set the whole header itself would silently drop
  // the framing clause — the page would work, the script would run, and RFC
  // 9700 section 4.14's protection would be gone.
  //
  // It is used for EVERY response of this handler and of the GET beside it,
  // rather than only for the armed-ceremony one. A page that carried the script
  // only sometimes would be a policy that changes under a reader, and the two
  // states of this page differ by a form.
  // ---------------------------------------------------------------------------
  private sendKeysPage(res, status, html) {
    const { app, log } = this.deps;
    log.debug("Entering Portal.sendKeysPage().");
    res.set('Content-Security-Policy',
            app.contentSecurityPolicy({ 'script-src': "'self'" }));
    res.status(status).set('Cache-Control', 'no-store').type('html').send(html);
    log.debug("Leaving Portal.sendKeysPage().");
  }

  // EVERY PATH THIS MODULE REGISTERS, and the signed-in half of it is read off
  // NAV rather than listed again — a page added to the column is a page in this
  // list, and one removed leaves nothing behind for `sts_metadata.js` to report
  // as described-but-not-registered.
  paths(): string[] {
    const { log } = this.deps;
    log.debug("Entering Portal.paths().");
    log.debug("Leaving Portal.paths().");
    return NAV_PAGES.map(function (one) { return one.path; })
      // The paths that are NOT pages in the column: the activation flow, the
      // OIDC redirect URI, the two form targets — and, since 2026-09-10, this
      // portal's Shared Signals RECEIVE endpoint, which is a page in no sense
      // at all. It is here because `sts_metadata.js` reads this list to check
      // the router against its own descriptions, and a route registered and
      // undescribed fails the suite.
      .concat([ACTIVATE, BASE + '/callback', BASE + '/remove-key',
               BASE + '/signout', BASE + '/signals/receive']);
  }

  registerRoutes(app: typeof import('../common/app')): void {
    const self = this;
    const { accessGate, accountSignals, audit, authn, baseUrlOf, config,
            credentials, errorCodes, log, oidcRp, parseBody, personAssertions,
            pki, signals, tlsClient, totp, validation,
            websecurity } = this.deps;
    log.debug("Entering Portal.registerRoutes().");

    // -------------------------------------------------------------------------
    // THE PORTAL RENEWS ITS OWN TOKENS BEFORE ANY PAGE READS ITS SESSION
    // (2026-09-12).
    //
    // `requireSignIn()` is synchronous and is called from inside every handler,
    // so the renewal cannot live there; it is ONE middleware on the whole
    // `/portal` prefix, registered above the first route in this module
    // (rule 1), so a page added tomorrow is renewed by construction. When the
    // session's ID Token and access token run out it redeems the refresh token
    // and writes the new tokens onto the same session — the person stays
    // signed in and on the page they asked for. `common/oidc_rp.ts`'s
    // section 4 argues all of it. It answers no request itself; a renewal that
    // could not happen ends the session, and `requireSignIn()` then sends the
    // browser through the code flow as it always did for a request with no
    // session.
    // -------------------------------------------------------------------------
    app.use(BASE, oidcRp.renewal('portal'));

    // ASYNCHRONOUS SINCE 2026-09-14 (#46): the rate limit below counts in the
    // cluster's shared window (`websecurity.attemptShared()`), a round trip.
    // Every limiter on this file's pages does the same, for one budget across
    // nodes.
    app.get(ACTIVATE, async function (req, res) {
      log.debug('Entering GET ' + ACTIVATE + '.');
      const asked = validation.check(req, 'query', ACTIVATE_QUERY);
      if (!asked.ok) {
        errorCodes.mark(res, self.innerCode(asked) || 'STS-PORTAL-0001');
        return self.refuseShape(res, asked);
      }
      const username = String(asked.value.user || '').trim();
      const token = String(asked.value.token || '');
      // RATE LIMITED even on the GET: this endpoint takes a credential, and an
      // endpoint that takes a credential must not be the one place in this
      // service that answers guesses at network speed.
      const allowed = await websecurity.attemptShared('activation', req,
                                                      username);
      if (!allowed.ok) {
        log.debug('Leaving GET ' + ACTIVATE + '. Rate limited.');
        errorCodes.mark(res, self.innerCode(allowed) || 'STS-PORTAL-0002');
        return self.send(res, 429, self.page('Too many attempts',
          '<div class="card"><h1>Too many attempts</h1><p>' +
          self.esc(allowed.detail) + '</p></div>'));
      }
      const checked = credentials.checkActivation(username, token);
      if (!checked.ok) {
        log.info('portal: an activation link was refused for "' + username +
                 '" (' + checked.reason + ').');
        audit.record({
          category: 'authentication', action: 'portal.activate.refused',
          errorCode: self.innerCode(checked) || 'STS-PORTAL-0003',
          actor: username, outcome: 'failure',
          summary: 'an activation link was refused',
          detail: { reason: checked.reason,
                    address: websecurity.addressOf(req) }
        });
        log.debug('Leaving GET ' + ACTIVATE + '. Refused.');
        errorCodes.mark(res, self.innerCode(checked) || 'STS-PORTAL-0003');
        return self.send(res, 400, self.page('Activation link',
          '<div class="card"><h1>Activation link</h1><div class="err">' +
          self.esc(ACTIVATION_REFUSAL) + '</div></div>'));
      }
      log.debug('Leaving GET ' + ACTIVATE + '. Drawing the setup form.');
      return self.send(res, 200,
                       self.activationForm(baseUrlOf(req), username, token,
                                           null, null));
    });

    app.post(ACTIVATE, async function (req, res) {
      log.debug('Entering POST ' + ACTIVATE + '.');
      // `parseBody()` and not `req.body`: this service parses every body as raw
      // text, so `checkParsed()` is the entry point. Its header argues why.
      const posted = validation.checkParsed(parseBody(req), 'body',
                                            ACTIVATE_FORM);
      if (!posted.ok) {
        errorCodes.mark(res, self.innerCode(posted) || 'STS-PORTAL-0001');
        return self.refuseShape(res, posted);
      }
      const body = posted.value;
      const username = String(body.user || '').trim();
      const token = String(body.token || '');
      const base = baseUrlOf(req);

      const allowed = await websecurity.attemptShared('activation', req,
                                                      username);
      if (!allowed.ok) {
        log.debug('Leaving POST ' + ACTIVATE + '. Rate limited.');
        errorCodes.mark(res, self.innerCode(allowed) || 'STS-PORTAL-0002');
        return self.send(res, 429, self.page('Too many attempts',
          '<div class="card"><h1>Too many attempts</h1><p>' +
          self.esc(allowed.detail) + '</p></div>'));
      }
      // **THE TOKEN IS CHECKED AGAIN ON THE POST**, and not merely on the GET
      // that drew the form. A form is markup; the door is here. A POST
      // assembled by hand never met the GET at all.
      const checked = credentials.checkActivation(username, token);
      if (!checked.ok) {
        log.info('portal: an activation POST was refused for "' + username +
                 '" (' + checked.reason + ').');
        log.debug('Leaving POST ' + ACTIVATE + '. Refused.');
        errorCodes.mark(res, self.innerCode(checked) || 'STS-PORTAL-0003');
        return self.send(res, 400, self.page('Activation link',
          '<div class="card"><h1>Activation link</h1><div class="err">' +
          self.esc(ACTIVATION_REFUSAL) + '</div></div>'));
      }
      // **SPENT IN THE STORE BEFORE ANYTHING IS SET**, and given back unless
      // this request finishes the activation — see `holdLinkClaim()`.
      const spent = await credentials.spendActivation(username, token);
      if (!spent.ok) {
        log.info('portal: an activation POST was refused for "' + username +
                 '" (' + spent.reason + ').');
        log.debug('Leaving POST ' + ACTIVATE + '. The link is being spent.');
        return self.refuseSpentLink(req, res, username, spent,
                               'portal.activate.refused', ACTIVATION_REFUSAL,
                               'Activation link');
      }
      self.holdLinkClaim(res, spent.handle);

      const password = String(body.password || '');
      const confirm = String(body.confirm || '');
      const keyRole = String(body.key_role || 'none');
      const wantsTotp = String(body.totp || '') === '1';
      const step = String(body.step || 'setup');

      // ---------------------------------------------------------------------
      // THE SECOND POST: A CODE, FOR AN ENROLMENT THAT IS ALREADY WAITING.
      //
      // It is handled FIRST and returns through the same finish below, which is
      // the arrangement that keeps one exit: the link is consumed, the audit
      // row is written and the account-ready page is drawn in exactly one
      // place, so the two paths cannot come to disagree about what finishing
      // means.
      //
      // The password guards underneath do not run on this path and must not:
      // this POST carries no password fields — the password was set on the
      // first one — so *set a password or choose a security key* would refuse
      // somebody who has already done both.
      // ---------------------------------------------------------------------
      if (step === 'totp') {
        const waiting = await self.pendingEnrolmentFor(username, base);
        if (!waiting) {
          log.debug('Leaving POST ' + ACTIVATE + '. The enrolment had ' +
                                                 'expired.');
          errorCodes.mark(res, 'STS-PORTAL-0004');
          return self.send(res, 400, self.activationForm(
            base, username, token, null,
            'That authenticator setup expired before it was confirmed. ' +
            'Nothing was lost — set it up again below, or leave the box ' +
            'unticked and use your password alone.'));
        }
        const confirmed = credentials.confirmTotpEnrolment(
          username, String(body.code || ''));
        if (!confirmed.ok) {
          audit.record({
            category: 'authentication', action: 'portal.activate.mfa.refused',
            errorCode: self.innerCode(confirmed) || 'STS-PORTAL-0005',
            actor: username, outcome: 'failure',
            summary: 'an authenticator app was not confirmed during activation',
            detail: { reason: confirmed.reason || '',
                      address: websecurity.addressOf(req) }
          });
          log.debug('Leaving POST ' + ACTIVATE + '. The code did not confirm.');
          // THE SAME SECRET IS REDRAWN. Mistyping six digits must not mean
          // scanning again.
          errorCodes.mark(res, self.innerCode(confirmed) || 'STS-PORTAL-0005');
          return self.send(res, 400, self.activationTotpForm(
            username, token, waiting,
            (confirmed.errors || ['That code is not right.'])[0]));
        }
        log.info('portal: ' + username + ' set up an authenticator app while ' +
                 'spending an activation link.');
        // THE RECOVERY CODES ARE CARRIED THROUGH RATHER THAN FETCHED AT THE FAR
        // END (2026-09-11). There is no list to hand back any more: enrolling a
        // second factor no longer issues one, because a set is HASHED and a
        // hash can only be made while the code is in the clear. Somebody who
        // activates an account with a second factor lands on the portal with
        // the prompt to generate one, which is what `recoveryAdvised` is for.
        //
        // **THIS IS THE WEAKEST POINT OF THE NEW ARRANGEMENT AND IT IS WHERE
        // THE OLD ONE WAS STRONGEST**: an activation is precisely the moment
        // somebody is paying attention and will never be paying attention
        // again. It is answered by the prompt being standing rather than a
        // one-off — the card stays in its warning state for as long as it is
        // true.
        return self.finishActivation(res, base, username, true, keyRole, true,
                                     req, null, null);
      }

      if (password && password !== confirm) {
        errorCodes.mark(res, 'STS-PORTAL-0006');
        return self.send(res, 400, self.activationForm(
          base, username, token, null, 'The two passwords do not match.'));
      }
      // **AT LEAST ONE WAY IN, AND THE COMBINATION THAT IS NOT ONE IS REFUSED
      // HERE.** A security key marked `mfa` is a SECOND factor — it is not a
      // way to sign in by itself — so choosing it with no password would finish
      // the setup with an account nobody can use, including its owner. That is
      // the same lockout `credentials.removeKey()` refuses to create, caught at
      // the other end of the same rule.
      if (!password && keyRole !== 'primary') {
        errorCodes.mark(res, 'STS-PORTAL-0007');
        return self.send(res, 400, self.activationForm(
          base, username, token, null,
          keyRole === 'mfa'
            ? 'A security key used as a SECOND factor needs a password to be ' +
              'the first one. Set a password as well, or choose to use the ' +
              'key instead of a password.'
            : 'Set a password, or choose to use a security key instead of ' +
              'one. You need at least one way to sign in.'));
      }
      if (password) {
        const set = credentials.setPassword(username, password);
        if (!set.ok) {
          errorCodes.mark(res, self.innerCode(set) || 'STS-PORTAL-0008');
          return self.send(res, 400, self.activationForm(
            base, username, token, null,
            (set.errors || ['The password could not be set.'])[0]));
        }
      }

      // ---------------------------------------------------------------------
      // THE AUTHENTICATOR APP, IF IT WAS ASKED FOR (2026-09-10).
      //
      // **THIS RETURNS WITHOUT FINISHING**, which is the whole shape of the
      // two-step enrolment: the password is set, the link is NOT spent, and the
      // person is shown a secret they have to prove they hold.
      // `finishActivation()` runs on the second POST.
      //
      // **THE SETTING IS CHECKED HERE AND NOT ONLY WHERE THE BOX IS DRAWN.**
      // The form is markup and this is the door — `authn.js`'s rule about the
      // anonymous button, and it applies to every optional control in this
      // service.
      //
      // A REFUSAL DOES NOT LOSE THE ACTIVATION. If the enrolment cannot be
      // started — the mechanism is off, or product mode will not enrol for
      // somebody with no entry — the setup FINISHES with what was configured
      // and says what did not happen. Refusing the whole activation over an
      // optional second factor would strand somebody who has just set a
      // perfectly good password.
      if (wantsTotp && totp.offered()) {
        const begun = credentials.beginTotpEnrolment(username, { base: base });
        if (begun.ok) {
          const enrolment = await self.pendingEnrolmentFor(username, base);
          if (enrolment) {
            audit.record({
              category: 'authentication', action: 'portal.activate.mfa.started',
              actor: username, outcome: 'success',
              summary: username + ' started setting up an authenticator app ' +
                       'while activating',
              detail: { address: websecurity.addressOf(req) }
            });
            log.debug('Leaving POST ' + ACTIVATE + '. Showing the ' +
                      'authenticator secret; the link is not spent yet.');
            return self.send(res, 200,
                             self.activationTotpForm(username, token,
                                                     enrolment, null));
          }
        }
        log.warn(errorCodes.tag('STS-PORTAL-0009') +
                 'portal: an authenticator app was asked for while ' +
                 'activating "' + username + '" and could not be started (' +
                 (begun.errors || []).join(' ') + '). The activation ' +
                 'finishes without it rather than being refused.');
        return self.finishActivation(res, base, username, !!password, keyRole,
                                     false, req,
                                     'The authenticator app could NOT be set ' +
                                     'up: ' +
                                     (begun.errors || ['it was refused.'])[0] +
                                     ' Everything else is set up, and you ' +
                                     'can add one from your account pages ' +
                                     'after you sign in.');
      }

      return self.finishActivation(res, base, username, !!password, keyRole,
                                   false, req);
    });

    // ASYNCHRONOUS SINCE 2026-09-14 (#46), for GET ACTIVATE's reason.
    app.get(RESET_PASSWORD, async function (req, res) {
      log.debug('Entering GET ' + RESET_PASSWORD + '.');
      const asked = validation.check(req, 'query', RESET_QUERY);
      if (!asked.ok) {
        errorCodes.mark(res, self.innerCode(asked) || 'STS-PORTAL-0001');
        log.debug('Leaving GET ' + RESET_PASSWORD + '. Bad shape.');
        return self.refuseShape(res, asked);
      }
      const username = String(asked.value.user || '').trim();
      const token = String(asked.value.token || '');
      const allowed = await websecurity.attemptShared('password-reset', req,
                                                      username);
      if (!allowed.ok) {
        errorCodes.mark(res, self.innerCode(allowed) || 'STS-PORTAL-0070');
        log.debug('Leaving GET ' + RESET_PASSWORD + '. Rate limited.');
        return self.send(res, 429, self.page('Too many attempts',
          '<div class="card"><h1>Too many attempts</h1><p>' +
          self.esc(allowed.detail) + '</p></div>'));
      }
      const checked = credentials.checkPasswordReset(username, token);
      if (!checked.ok) {
        log.info('portal: a password reset link was refused for "' + username +
                 '" (' + checked.reason + ').');
        audit.record({
          category: 'authentication', action: 'portal.password-reset.refused',
          errorCode: self.innerCode(checked) || 'STS-PORTAL-0071',
          actor: username, outcome: 'failure',
          summary: 'a password reset link was refused',
          detail: { reason: checked.reason,
                    address: websecurity.addressOf(req) }
        });
        log.debug('Leaving GET ' + RESET_PASSWORD + '. Refused.');
        return self.refuseResetLink(res, 400,
                                    self.innerCode(checked) ||
                                      'STS-PORTAL-0071');
      }
      log.debug('Leaving GET ' + RESET_PASSWORD + '. Drawing the form.');
      return self.send(res, 200, self.resetPasswordForm(baseUrlOf(req),
                                                        username, token,
                                                        null));
    });

    app.post(RESET_PASSWORD, async function (req, res) {
      log.debug('Entering POST ' + RESET_PASSWORD + '.');
      const posted = validation.checkParsed(parseBody(req), 'body', RESET_FORM);
      if (!posted.ok) {
        errorCodes.mark(res, self.innerCode(posted) || 'STS-PORTAL-0001');
        log.debug('Leaving POST ' + RESET_PASSWORD + '. Bad shape.');
        return self.refuseShape(res, posted);
      }
      const body = posted.value;
      const username = String(body.user || '').trim();
      const token = String(body.token || '');
      const base = baseUrlOf(req);
      const allowed = await websecurity.attemptShared('password-reset', req,
                                                      username);
      if (!allowed.ok) {
        errorCodes.mark(res, self.innerCode(allowed) || 'STS-PORTAL-0070');
        log.debug('Leaving POST ' + RESET_PASSWORD + '. Rate limited.');
        return self.send(res, 429, self.page('Too many attempts',
          '<div class="card"><h1>Too many attempts</h1><p>' +
          self.esc(allowed.detail) + '</p></div>'));
      }
      // **CHECKED AGAIN ON THE POST**, for the activation form's reason: a form
      // is markup, and a POST assembled by hand never met the GET.
      const checked = credentials.checkPasswordReset(username, token);
      if (!checked.ok) {
        audit.record({
          category: 'authentication', action: 'portal.password-reset.refused',
          errorCode: self.innerCode(checked) || 'STS-PORTAL-0071',
          actor: username, outcome: 'failure',
          summary: 'a password reset link was refused',
          detail: { reason: checked.reason,
                    address: websecurity.addressOf(req) }
        });
        log.debug('Leaving POST ' + RESET_PASSWORD + '. Refused.');
        return self.refuseResetLink(res, 400,
                                    self.innerCode(checked) ||
                                      'STS-PORTAL-0071');
      }
      const password = String(body.password || '');
      if (!password) {
        errorCodes.mark(res, 'STS-PORTAL-0072');
        log.debug('Leaving POST ' + RESET_PASSWORD + '. No password.');
        return self.send(res, 400, self.resetPasswordForm(base, username, token,
          'Type a new password, twice.'));
      }
      if (password !== String(body.confirm || '')) {
        errorCodes.mark(res, 'STS-PORTAL-0072');
        log.debug('Leaving POST ' + RESET_PASSWORD + '. They differ.');
        return self.send(res, 400, self.resetPasswordForm(base, username, token,
          'The two passwords do not match.'));
      }
      if (password === credentials.RESERVED_REFUSAL) {
        errorCodes.mark(res, 'STS-PORTAL-0072');
        log.debug('Leaving POST ' + RESET_PASSWORD + '. The reserved ' +
          'password.');
        return self.send(res, 400, self.resetPasswordForm(base, username, token,
          'That password is reserved and is refused at every sign-in, so it ' +
          'cannot be yours.'));
      }
      // **SPENT IN THE STORE BEFORE THE PASSWORD IS SET**, and given back
      // unless the password is stored — see `holdLinkClaim()`.
      const spent = await credentials.spendPasswordReset(username, token);
      if (!spent.ok) {
        log.debug('Leaving POST ' + RESET_PASSWORD + '. The link is being ' +
          'spent.');
        return self.refuseSpentLink(req, res, username, spent,
                               'portal.password-reset.refused', RESET_REFUSAL,
                               'Password reset link');
      }
      self.holdLinkClaim(res, spent.handle);
      const set = credentials.setPassword(username, password);
      if (!set.ok) {
        errorCodes.mark(res, self.innerCode(set) || 'STS-PORTAL-0073');
        log.debug('Leaving POST ' + RESET_PASSWORD + '. The password was ' +
          'refused.');
        return self.send(res, 400, self.resetPasswordForm(base, username, token,
          (set.errors || ['The password could not be set.'])[0]));
      }
      res[LINK_SPENT] = true;
      credentials.consumePasswordReset(username);
      credentials.setPasswordResetRequired(username, false);
      await websecurity.succeededShared('password-reset', req, username);
      audit.record({
        category: 'authentication', action: 'portal.password-reset',
        actor: username, target: username, outcome: 'success',
        summary: username + ' chose a new password from a reset link',
        detail: { address: websecurity.addressOf(req) }
      });
      accountSignals.credentialChanged({ username: username,
        credentialType: 'password', changeType: 'create',
        initiatingEntity: 'user', via: 'portal',
        reasonAdmin: username + ' set a new password from a password reset ' +
                                'link.',
        reasonUser: 'You chose a new password.' });
      log.info('portal: ' + username + ' set a new password from a reset ' +
               'link; the link is spent.');
      log.debug('Leaving POST ' + RESET_PASSWORD + '. Set.');
      return self.send(res, 200, self.page('Password set',
        '<div class="card"><h1>Your password is set</h1>' +
        '<div class="ok">This reset link has now been used and will not work ' +
        'again.</div>' +
        '<p>Sign in with your new password. If your account has a second ' +
        'factor, you will be asked for it as usual.</p>' +
        // `/portal` and not the sign-in screen, for `finishActivation()`'s
        // reason: `/authn/login` draws a form for a pending record, and
        // `/portal` is what mints one when the link is pressed.
        '<p><a href="' + self.esc(self.signInHref()) + '">Sign ' +
          'in</a></p></div>'));
    });

    // =========================================================================
    // THE REDIRECT URI. WHERE THE AUTHORIZATION ENDPOINT SENDS THE BROWSER
    // BACK.
    //
    // Registered ABOVE the portal's own pages so that a reader meets it beside
    // `requireSignIn()`, which is the function that sends people away in the
    // first place. There is no gate over `/portal` — every page here calls
    // `requireSignIn()` itself — so unlike the console's callback this one
    // needs no exemption from anything; it simply does not call that function.
    //
    // Everything it does is in `common/oidc_rp.ts`. What is here is where to go
    // afterwards and what a refusal looks like in the portal's own shell, which
    // is a different application from the console's and draws its own.
    // =========================================================================
    app.get(BASE + '/callback', function (req, res) {
      log.debug('Entering ' + BASE + '/callback.');
      oidcRp.handleCallback(req, res, 'portal').then(function (answer) {
        if (!answer.ok) {
          log.info('portal: a sign-in did not complete. ' + answer.why);
          errorCodes.mark(res, self.innerCode(answer) || 'STS-PORTAL-0012');
          self.send(res, 400, self.page('Signing in did not complete',
            '<div class="card"><h1>Signing in did not complete</h1>' +
            '<div class="err">' + self.esc(answer.why) + '</div><p>This ' +
            'portal signs you in through this service\'s own sign-in ' +
            'service, using the ordinary OpenID Connect authorization code ' +
            'flow — the same one any other application here would use. What ' +
            'failed above is one step of that flow, named exactly rather ' +
            'than reported as &ldquo;sign-in failed&rdquo;.</p><p><a ' +
            'href="' + self.esc(BASE) + '">Try again</a></p></div>'));
          log.debug('Leaving ' + BASE + '/callback. Refused.');
          return;
        }
        res.status(303).set('Cache-Control', 'no-store')
           .set('Location', answer.returnTo || BASE).end();
        log.debug('Leaving ' + BASE + '/callback. Signed in ' +
                                      'as ' + answer.username +
                  '.');
      }).catch(function (e) {
        // A rejection is a bug here rather than anything a request can cause:
        // handleCallback() resolves its refusals. Reported as one.
        log.error(errorCodes.tag('STS-PORTAL-0013') + 'The portal OIDC ' +
                                                      'callback threw: ' +
                  (e.stack || e.message));
        errorCodes.mark(res, 'STS-PORTAL-0013');
        self.send(res, 500, self.page('Signing in did not complete',
          '<div class="card"><h1>Signing in did not complete</h1>' +
          '<div class="err">' + self.esc(e.message) + '</div></div>'));
      });
    });

    // -------------------------------------------------------------------------
    // THE SIGNED-IN PAGES. Each one is the same four steps in the same order,
    // and the order is the point: SIGN IN (which is also the access decision),
    // then VALIDATE what was asked for, then draw.
    //
    // **THE `returnTo` IS THE PAGE ITSELF ON EVERY ONE OF THEM.** Somebody who
    // follows a link to their security keys with no session runs the code flow
    // and comes back to their security keys, rather than to the overview with
    // the page they asked for forgotten. `oidc_rp.js` holds it server-side and
    // refuses anything that is not a path on this service, so a `returnTo` per
    // page is no more of an open-redirect surface than one was.
    //
    // **AND THE ACTION IS `READ`, NOT `MANAGE_OWN`.** Drawing a page is
    // reading; the POSTs below ask for `manage-own`. That distinction is the
    // whole reason the portal has an action of its own — see `requireSignIn()`,
    // where the policy question is argued — and a deployment that later gives a
    // helpdesk role the right to READ somebody's account without changing it
    // needs the two to have been kept apart from the beginning.
    // -------------------------------------------------------------------------
    app.get(BASE, function (req, res) {
      log.debug('Entering GET ' + BASE + '.');
      const session = self.requireSignIn(req, res, BASE,
                                         accessGate.ACTION.READ);
      if (!session) {
        log.debug('Leaving GET ' + BASE + '. Not signed in, or not permitted.');
        return undefined;
      }
      const asked = validation.check(req, 'query', PORTAL_QUERY);
      if (!asked.ok) {
        errorCodes.mark(res, self.innerCode(asked) || 'STS-PORTAL-0001');
        return self.refuseShape(res, asked);
      }
      log.debug('Leaving GET ' + BASE + '. Drawn for ' + session.user.username +
                '.');
      return self.send(res, 200, self.overviewPage(session,
        asked.value.done ? String(asked.value.done) : null, null));
    });

    app.get(BASE + '/applications', function (req, res) {
      log.debug('Entering GET ' + BASE + '/applications.');
      const session = self.requireSignIn(req, res, BASE + '/applications',
                                    accessGate.ACTION.READ);
      if (!session) {
        log.debug('Leaving GET ' + BASE + '/applications. Not signed in, or ' +
                  'not permitted.');
        return undefined;
      }
      const asked = validation.check(req, 'query', APPLICATIONS_QUERY);
      if (!asked.ok) {
        errorCodes.mark(res, self.innerCode(asked) || 'STS-PORTAL-0001');
        return self.refuseShape(res, asked);
      }
      log.debug('Leaving GET ' + BASE + '/applications. Drawn for ' +
                session.user.username + '.');
      return self.send(res, 200, self.applicationsPage(session,
        asked.value.done ? String(asked.value.done) : null, null,
        asked.value.page || 1));
    });

    // -------------------------------------------------------------------------
    // THE RECEIVE ENDPOINT.
    //
    // **IT IS AN UNAUTHENTICATED ROUTE IN THIS FILE AND THE FIRST THAT IS NOT A
    // PERSON.** `/portal/activate` was the other when it was written
    // (`/portal/reset-password` joined them on 2026-09-13), and its header says
    // why those are the only routes here that take an identity from the request
    // — nobody is signed in yet and the TOKEN is what authorises it. This one
    // takes no identity at all: what arrives is a Security Event Token
    // addressed to this portal, and what authorises it is the bearer token on
    // this portal's OWN stream, minted per start and given to nothing but this
    // service's own transmitter. `accept()` checks it in constant time, checks
    // the audience, verifies the signature, and records what arrived either
    // way.
    //
    // **IT IS DELIBERATELY NOT RATE LIMITED**, which every credential endpoint
    // in this file is. A push is a machine delivering an event that has already
    // happened; a limiter would silently drop somebody's account-disabled
    // notice under load, which is the one kind of message that must not be
    // dropped quietly. The credential is the bound here, and
    // `ssf.maxReceivedEvents` is the ceiling on what is kept.
    // -------------------------------------------------------------------------
    app.post(BASE + '/signals/receive', function (req, res) {
      log.debug('Entering POST ' + BASE + '/signals/receive.');
      const taken = signals.accept(signals.PORTAL, req);
      if (taken.status >= 400) {
        // The receiver's own code where it gave one; this portal's door
        // otherwise.
        errorCodes.mark(res, self.innerCode(taken) || 'STS-PORTAL-0038');
      }
      res.status(taken.status).set('Cache-Control', 'no-store');
      if (taken.body) {
        res.type('application/json').send(JSON.stringify(taken.body, null, 2));
      } else {
        // 202 with an EMPTY body, which is what RFC 8935 section 2.3 says.
        res.end();
      }
      log.debug('Leaving ' +
                'POST ' + BASE + '/signals/receive. ' + taken.status + '.');
    });

    app.get(BASE + '/signals', function (req, res) {
      log.debug('Entering GET ' + BASE + '/signals.');
      const session = self.requireSignIn(req, res, BASE + '/signals',
                                    accessGate.ACTION.READ);
      if (!session) {
        log.debug('Leaving GET ' + BASE + '/signals. Not signed in, or not ' +
                  'permitted.');
        return undefined;
      }
      const asked = validation.check(req, 'query', SIGNALS_QUERY);
      if (!asked.ok) {
        errorCodes.mark(res, self.innerCode(asked) || 'STS-PORTAL-0001');
        return self.refuseShape(res, asked);
      }
      log.debug('Leaving GET ' + BASE + '/signals. Drawn for ' +
                session.user.username + '.');
      return self.send(res, 200, self.signalsPage(session, null, null,
                                        asked.value.page || 1));
    });

    // THE ACCOUNT HOLDER'S RISC CHOICE (#146). See participationCard().
    app.post(BASE + '/signals', async function (req, res) {
      log.debug('Entering POST ' + BASE + '/signals.');
      const session = self.requireSignIn(req, res, BASE + '/signals',
                                         accessGate.ACTION.MANAGE_OWN);
      if (!session) {
        log.debug('Leaving POST ' + BASE + '/signals. Not signed in.');
        return undefined;
      }
      const username = session.user.username;
      const posted = validation.checkParsed(parseBody(req), 'body',
                                            PARTICIPATION_FORM);
      if (!posted.ok) {
        errorCodes.mark(res, self.innerCode(posted) || 'STS-PORTAL-0001');
        return self.refuseShape(res, posted);
      }
      const csrf = websecurity.checkCsrf(session.id, posted.value);
      if (!csrf.ok) {
        log.debug('Leaving POST ' + BASE + '/signals. CSRF.');
        errorCodes.mark(res, self.innerCode(csrf) || 'STS-PORTAL-0017');
        return self.send(res, 403, self.signalsPage(session, null,
                                                    csrf.detail, 1));
      }
      const { risc } = self.deps;
      const move = String(posted.value.move || '');
      if (!risc.enabled() || !risc.optOutMoveAllowed(username, move)) {
        log.debug('Leaving POST ' + BASE + '/signals. Not a move from ' +
                  'here.');
        errorCodes.mark(res, 'STS-PORTAL-0075');
        return self.send(res, 409, self.signalsPage(session, null,
          'That is not a change your account can make now: it is ' +
          risc.optOutOf(username).state + '.', 1));
      }
      const before = risc.optOutOf(username).state;
      await self.deps.accountSignals.optOutMoved({ username: username,
        act: move, via: 'portal',
        reasonAdmin: username + ' changed their RISC participation on the ' +
                     'portal.' });
      const after = risc.optOutOf(username).state;
      if (after === before) {
        // Nothing recorded it — Shared Signals is off in this process, so
        // there is no register to move and no receiver to tell.
        log.warn(errorCodes.tag('STS-PORTAL-0076') + 'portal: ' + username +
                 '\'s RISC ' + move + ' was not recorded.');
        errorCodes.mark(res, 'STS-PORTAL-0076');
        return self.send(res, 503, self.signalsPage(session, null,
          'Your choice could not be recorded: this service is not ' +
          'sending security events at the moment.', 1));
      }
      audit.record({
        category: 'signals', action: 'portal.risc.' + move,
        actor: username, outcome: 'success',
        summary: username + ' moved their RISC participation from ' + before +
                 ' to ' + after,
        detail: { address: websecurity.addressOf(req) }
      });
      log.debug('Leaving POST ' + BASE + '/signals. ' + before + ' -> ' +
                after + '.');
      return self.send(res, 200, self.signalsPage(session,
        after === 'opt-out-initiated'
          ? 'You asked to stop sharing security events. It takes effect ' +
            'after the waiting period, and you can cancel until then.'
          : after === 'opt-in'
            ? 'Security events about your account are shared.'
            : 'Done.', null, 1));
    });

    // THE PAGE BEHIND THE POST BELOW. Same path, different method: the form has
    // to live somewhere now that it is not on the overview, and giving it a
    // path of its own would leave the form and the handler that answers it on
    // two addresses for no reason anybody could state.
    app.get(BASE + '/password', function (req, res) {
      log.debug('Entering GET ' + BASE + '/password.');
      const session = self.requireSignIn(req, res, BASE + '/password',
                                    accessGate.ACTION.READ);
      if (!session) {
        log.debug('Leaving GET ' + BASE + '/password. Not signed in, or not ' +
                  'permitted.');
        return undefined;
      }
      const asked = validation.check(req, 'query', PORTAL_QUERY);
      if (!asked.ok) {
        errorCodes.mark(res, self.innerCode(asked) || 'STS-PORTAL-0001');
        return self.refuseShape(res, asked);
      }
      log.debug('Leaving GET ' + BASE + '/password. Drawn for ' +
                session.user.username + '.');
      return self.send(res, 200, self.passwordPage(session,
        asked.value.done ? String(asked.value.done) : null, null));
    });

    app.get(BASE + '/keys', function (req, res) {
      log.debug('Entering GET ' + BASE + '/keys.');
      const session = self.requireSignIn(req, res, BASE + '/keys',
                                    accessGate.ACTION.READ);
      if (!session) {
        log.debug('Leaving GET ' + BASE +
                  '/keys. Not signed in, or not permitted.');
        return undefined;
      }
      const asked = validation.check(req, 'query', PORTAL_QUERY);
      if (!asked.ok) {
        errorCodes.mark(res, self.innerCode(asked) || 'STS-PORTAL-0001');
        return self.refuseShape(res, asked);
      }
      log.debug('Leaving GET ' + BASE + '/keys. Drawn for ' +
                session.user.username + '.');
      // THROUGH `sendKeysPage()`, which relaxes `script-src` to `'self'` — this
      // is the one page of this portal that carries a script, and it carries it
      // in both of its states. See that function's header.
      return self.sendKeysPage(res, 200, self.keysPage(session,
        asked.value.done ? String(asked.value.done) : null, null,
        baseUrlOf(req)));
    });

    // -------------------------------------------------------------------------
    // CHANGING A PASSWORD. Four controls in one handler, and each is a
    // different item on the list.
    //
    //   CSRF          the token this session's forms carry            (A01/A08)
    //   RATE LIMIT    so the current-password check is not an oracle  (A04/A07)
    //   RE-AUTH       the current password, even though signed in     (A07)
    //   SESSION       the identity from the session, never the body   (A01)
    // -------------------------------------------------------------------------

    // -------------------------------------------------------------------------
    // GET /portal/mfa — the authenticator app.
    //
    // **IT IS `async` AND IT WAS THE ONLY PAGE HERE THAT WAS**, because drawing
    // a QR code is asynchronous. (The link pages and several POSTs are `async`
    // too since 2026-09-14, for the cluster's shared rate-limit window.) That
    // is worth a sentence rather than being left to be noticed:
    // `common/CLAUDE.md`'s worker-pool section lists exactly four asynchronous
    // call paths in this service and this is not one of them — the work is a
    // few hundred microseconds of squares, not a post-quantum signature, and it
    // is `await`ed here rather than handed to the pool.
    //
    // `read` and not `manage-own` — drawing a page is reading, which is the
    // distinction the whole portal keeps and the reason it has an access-gate
    // action of its own.
    // -------------------------------------------------------------------------
    app.get(BASE + '/mfa', async function (req, res) {
      log.debug('Entering GET ' + BASE + '/mfa.');
      const session = self.requireSignIn(req, res, BASE + '/mfa',
                                    accessGate.ACTION.READ);
      if (!session) return undefined;
      const asked = validation.check(req, 'query', PORTAL_QUERY);
      if (!asked.ok) {
        errorCodes.mark(res, self.innerCode(asked) || 'STS-PORTAL-0001');
        return self.refuseShape(res, asked);
      }
      const enrolment = await self.pendingEnrolmentFor(session.user.username,
                                                  baseUrlOf(req));
      log.debug('Leaving GET ' + BASE + '/mfa.');
      return self.send(res, 200, self.mfaPage(session,
                                              asked.value.done || null, null,
                                              enrolment));
    });

    // -------------------------------------------------------------------------
    // POST /portal/mfa — start, confirm, remove.
    //
    // **ONE ENDPOINT AND THREE ACTIONS**, rather than three paths. They are
    // three steps of one thing, they all answer with this same page, and
    // `action` is a closed set the form itself draws — which is the shape
    // `/admin`'s action endpoints have had since the console was written, and
    // the reason `sts_metadata.js` can describe this as one entry.
    //
    // **`manage-own` FOR ALL THREE**, including `start`: minting a secret and
    // holding it is a change to how this person will sign in, even though
    // nothing is written to the directory until `confirm`. A deployment that
    // later lets a helpdesk role READ an account without changing it must not
    // have the enrolment door on the read side of that line.
    // -------------------------------------------------------------------------
    app.post(BASE + '/mfa', async function (req, res) {
      log.debug('Entering POST ' + BASE + '/mfa.');
      const session = self.requireSignIn(req, res, BASE + '/mfa',
                                    accessGate.ACTION.MANAGE_OWN);
      if (!session) return undefined;
      // THE IDENTITY IS THE SESSION'S AND THERE IS NO PARAMETER FOR IT. The
      // rule at the top of this file, and it matters more on this endpoint than
      // on any other here: a `username` read from this body would let anybody
      // signed in enrol THEIR OWN authenticator app as somebody else's second
      // factor, which is not an information leak but a takeover — they would
      // then hold the second factor for an account they do not own.
      const username = session.user.username;
      const posted = validation.checkParsed(parseBody(req), 'body', MFA_FORM);
      if (!posted.ok) {
        errorCodes.mark(res, self.innerCode(posted) || 'STS-PORTAL-0001');
        return self.refuseShape(res, posted);
      }
      const body = posted.value;
      const action = String(body.action || '');
      const base = baseUrlOf(req);

      const csrf = websecurity.checkCsrf(session.id, body);
      if (!csrf.ok) {
        log.warn('portal: an authenticator change for ' + username +
                 ' was refused on CSRF (' + csrf.reason + ').');
        audit.record({
          category: 'authentication', action: 'portal.mfa.csrf',
          errorCode: self.innerCode(csrf) || 'STS-PORTAL-0017',
          actor: username, outcome: 'failure',
          summary: 'an authenticator app change was refused: ' + csrf.reason,
          detail: { address: websecurity.addressOf(req), what: action }
        });
        log.debug('Leaving POST ' + BASE + '/mfa. CSRF.');
        errorCodes.mark(res, self.innerCode(csrf) || 'STS-PORTAL-0017');
        return self.send(res, 403, self.mfaPage(
          session, null, csrf.detail,
          await self.pendingEnrolmentFor(username, base)));
      }

      if (action === 'remove') {
        const removed = credentials.removeTotp(username);
        if (!removed.ok) {
          log.debug('Leaving POST ' + BASE + '/mfa. Nothing to remove.');
          errorCodes.mark(res, self.innerCode(removed) || 'STS-PORTAL-0021');
          return self.send(res, 400, self.mfaPage(session, null,
            (removed.errors || ['It could not be removed.'])[0],
            await self.pendingEnrolmentFor(username, base)));
        }
        audit.record({
          category: 'authentication', action: 'portal.mfa.removed',
          actor: username, outcome: 'success',
          summary: username + ' removed their own authenticator app',
          detail: { address: websecurity.addressOf(req) }
        });
        // CAEP credential-change (#145), as the console's clear-totp sends.
        self.deps.accountSignals.credentialChanged({ username: username,
          credentialType: self.deps.accountSignals.TOTP_CREDENTIAL_TYPE,
          changeType: 'delete', initiatingEntity: 'user', via: 'portal',
          reasonAdmin: username + ' removed their authenticator app.',
          reasonUser: 'You removed your authenticator app.' });
        log.info('portal: ' + username + ' removed their authenticator app. ' +
                 'That account is down to one factor.');
        log.debug('Leaving POST ' + BASE + '/mfa. Removed.');
        res.status(303).set('Location', BASE + '/mfa?done=' +
          encodeURIComponent('Your authenticator app is removed.')).end();
        return undefined;
      }

      if (action === 'start') {
        // **THE SETTING IS CHECKED AT THE DOOR AND NOT ONLY ON THE PAGE**,
        // which is `authn.js`'s rule about the anonymous button read again: the
        // page is markup and this is the door, so a form posted by hand while
        // `totp.enabled` is off must not mint a secret.
        const begun = credentials.beginTotpEnrolment(username, { base: base });
        if (!begun.ok) {
          log.debug('Leaving POST ' + BASE + '/mfa. Refused to start.');
          errorCodes.mark(res, self.innerCode(begun) || 'STS-PORTAL-0022');
          return self.send(res, 400, self.mfaPage(session, null,
            (begun.errors || ['The setup could not be started.'])[0], null));
        }
        audit.record({
          category: 'authentication', action: 'portal.mfa.started',
          actor: username, outcome: 'success',
          summary: username + ' started setting up an authenticator app',
          detail: { address: websecurity.addressOf(req) }
        });
        log.debug('Leaving POST ' + BASE + '/mfa. Secret minted and held.');
        // REDIRECT AND NOT A RENDER, so that the QR code survives a reload: a
        // rendered response to a POST is one the browser offers to re-submit,
        // and re-submitting `start` would mint a SECOND secret and invalidate
        // the code the person has just scanned.
        res.status(303).set('Location', BASE + '/mfa').end();
        return undefined;
      }

      if (action === 'confirm') {
        // RATE LIMITED. Six digits is a million values and this endpoint checks
        // them for real; the sign-in door's own code step is limited for the
        // same reason and with the same buckets.
        const allowed = await websecurity.attemptShared('mfa-code', req,
                                                        username);
        if (!allowed.ok) {
          log.debug('Leaving POST ' + BASE + '/mfa. Rate limited.');
          errorCodes.mark(res, self.innerCode(allowed) || 'STS-PORTAL-0018');
          return self.send(res, 429, self.mfaPage(
            session, null, allowed.detail,
            await self.pendingEnrolmentFor(username, base)));
        }
        const confirmed = credentials.confirmTotpEnrolment(
          username, String(body.code || ''));
        if (!confirmed.ok) {
          audit.record({
            category: 'authentication', action: 'portal.mfa.refused',
            errorCode: self.innerCode(confirmed) || 'STS-PORTAL-0023',
            actor: username, outcome: 'failure',
            summary: 'an authenticator app setup was not confirmed',
            detail: { reason: confirmed.reason || '',
                      address: websecurity.addressOf(req) }
          });
          log.debug('Leaving POST ' + BASE + '/mfa. The code did not confirm.');
          // THE SAME PENDING SECRET IS REDRAWN, not a new one. A mistyped code
          // is the ordinary case and re-scanning for a typo would be the reason
          // nobody finishes this.
          errorCodes.mark(res, self.innerCode(confirmed) || 'STS-PORTAL-0023');
          return self.send(res, 400, self.mfaPage(session, null,
            (confirmed.errors || ['That code is not right.'])[0],
            await self.pendingEnrolmentFor(username, base)));
        }
        audit.record({
          category: 'authentication', action: 'portal.mfa.enrolled',
          actor: username, outcome: 'success',
          summary: username + ' set up an authenticator app as a second factor',
          detail: { address: websecurity.addressOf(req) }
        });
        self.deps.accountSignals.credentialChanged({ username: username,
          credentialType: self.deps.accountSignals.TOTP_CREDENTIAL_TYPE,
          changeType: 'create', initiatingEntity: 'user', via: 'portal',
          reasonAdmin: username + ' set up an authenticator app.',
          reasonUser: 'You set up an authenticator app.' });
        await websecurity.succeededShared('mfa-code', req, username);
        log.info('portal: ' + username + ' set up an authenticator app. A ' +
                 'password alone will no longer sign them in.');
        // ---------------------------------------------------------------------
        // NO RECOVERY CODES ARE ISSUED BY THIS ENROLMENT ANY MORE (2026-09-11).
        //
        // This branch used to render rather than redirect, because a 303 cannot
        // carry a list of credentials and the response to this POST was the one
        // moment this service knew somebody was watching. It has nothing to
        // carry now: a set is generated when the person ASKS to see one, and is
        // stored — hashed — only when they confirm they have kept it.
        //
        // **WHAT IS LEFT IS THE NUDGE, AND IT IS CARRIED ON THE REDIRECT.** The
        // old arrangement protected the people who never think to ask; dropping
        // it without replacing it would be a worse service, so the message says
        // what they now have and what they do not, and the card below draws a
        // standing prompt for as long as it stays true.
        log.debug('Leaving POST ' + BASE + '/mfa. Enrolled.');
        res.status(303).set('Location', BASE + '/mfa?done=' +
          encodeURIComponent('Your authenticator app is set up. You will be ' +
                             'asked for a code the next time you sign in.' +
                             (confirmed.recoveryAdvised
                               ? ' You hold no recovery codes — generate a ' +
                                 'set below, before you need it.'
                               : ''))).end();
        return undefined;
      }

      // =====================================================================
      // THE RECOVERY CODES: GENERATE, CONFIRM, DISCARD (2026-09-11).
      //
      // **THIS REPLACES A SINGLE `show-codes` ACTION AND THE DIFFERENCE IS THE
      // WHOLE CHANGE.** That one read a stored set back and showed it, which is
      // what a set being ENCRYPTED bought; a set is HASHED now, so there is
      // nothing to read back and the only moment the codes exist is the one
      // that made them.
      //
      // Three actions because there are three things a person does, and the
      // middle one is the one that was asked for:
      //
      //   * `generate-codes` mints a set and SHOWS it. Nothing is stored.
      //   * `confirm-codes` is the *I have saved these* button. NOW they are
      //     hashed and written.
      //   * `discard-codes` throws the pending set away — the Cancel beside the
      //     Confirm, so somebody who decides they are not ready does not leave
      //     a live list in this process's memory for the rest of the TTL.
      //
      // **ALL THREE ARE POSTS**, for the reason the old one was: a list of
      // credentials drawn by a page merely loading is a list in a browser
      // history entry and on the back button, which `no-store` does not touch.
      // =====================================================================
      if (action === 'generate-codes') {
        const begun = credentials.beginBackupCodes(username);
        audit.record({
          category: 'authentication',
          action: 'portal.mfa.backup-codes.generated',
          errorCode: begun.ok ? undefined
            : (self.innerCode(begun) || 'STS-PORTAL-0024'),
          actor: username, outcome: begun.ok ? 'success' : 'failure',
          summary: begun.ok
            ? username + ' generated a set of recovery codes and is being ' +
              'shown it; nothing is stored until they confirm'
            : username + ' asked for a set of recovery codes and none could ' +
              'be generated',
          detail: { count: begun.ok ? begun.codes.length : 0,
                    replacing: !!begun.replacing,
                    address: websecurity.addressOf(req),
                    errors: begun.ok ? undefined : (begun.errors || []) }
        });
        if (!begun.ok) {
          log.debug('Leaving POST ' + BASE + '/mfa. Could not generate.');
          errorCodes.mark(res, self.innerCode(begun) || 'STS-PORTAL-0024');
          return self.send(res, 400, self.mfaPage(session, null,
            (begun.errors || ['They could not be generated.'])[0],
            await self.pendingEnrolmentFor(username, base), null, null));
        }
        log.info('portal: ' + username + ' generated a set of recovery ' +
                 'codes. They are being SHOWN and nothing is stored yet.');
        log.debug('Leaving POST ' + BASE + '/mfa. Generated and showing.');
        // **RENDERED AND NOT REDIRECTED**, which is the one place this endpoint
        // does that: a 303 cannot carry a list of credentials, and putting them
        // on a query string would write them into a browser history entry and
        // every proxy log between here and the person.
        return self.send(res, 200, self.mfaPage(session, null, null, null,
                                                begun, null));
      }

      if (action === 'confirm-codes') {
        const stored = credentials.confirmBackupCodes(
          username, String(body.handle || ''));
        // RECOVERY CODES ARE RECOVERY INFORMATION (#145): CAEP names no
        // credential type for them, and RISC's recovery-information-changed
        // is the event the console's clear already sends.
        if (stored.ok) {
          self.deps.accountSignals.recoveryInformationChanged({
            username: username, via: 'portal' });
        }
        audit.record({
          category: 'authentication',
          action: 'portal.mfa.backup-codes.confirmed',
          errorCode: stored.ok ? undefined :
                     (self.innerCode(stored) || 'STS-PORTAL-0025'),
          actor: username, outcome: stored.ok ? 'success' : 'failure',
          summary: stored.ok
            ? username + ' confirmed they had saved their recovery codes, ' +
              'and the hashes were stored'
            : username + ' tried to confirm a set of recovery codes and it ' +
              'could not be stored',
          detail: { total: stored.ok ? stored.total : 0,
                    address: websecurity.addressOf(req),
                    errors: stored.ok ? undefined : (stored.errors || []) }
        });
        if (!stored.ok) {
          // **THE PENDING SET SURVIVES A FAILED WRITE AND THE PAGE REDRAWS WITH
          // THE CODES STILL ON IT** where it can. The person is looking at a
          // list they may already have written down; sending them back to an
          // empty page would throw that away for a failure that pressing the
          // button again may well fix.
          const held = credentials.pendingBackupCodesFor(
            username, String(body.handle || ''));
          log.debug('Leaving POST ' + BASE + '/mfa. The confirm failed.');
          errorCodes.mark(res, self.innerCode(stored) || 'STS-PORTAL-0025');
          return self.send(res, 400, self.mfaPage(session, null,
            (stored.errors || ['They could not be stored.'])[0],
            null,
            held ? { ok: true, handle: String(body.handle || ''),
                     codes: held.codes, total: held.codes.length } : null,
            null));
        }
        log.debug('Leaving POST ' + BASE + '/mfa. Confirmed and stored.');
        res.status(303).set('Location', BASE + '/mfa?done=' +
          encodeURIComponent('Your ' + stored.total + ' recovery codes are ' +
                             'saved. Only their hashes are stored, so this ' +
                             'service can never show them to you again — ' +
                             'keep the copy you made.')).end();
        return undefined;
      }

      if (action === 'discard-codes') {
        credentials.discardBackupCodes(username, String(body.handle || ''));
        audit.record({
          category: 'authentication',
          action: 'portal.mfa.backup-codes.discarded',
          actor: username, outcome: 'success',
          summary: username + ' threw away a set of recovery codes without ' +
                   'storing it',
          detail: { address: websecurity.addressOf(req) }
        });
        log.debug('Leaving POST ' + BASE + '/mfa. Discarded.');
        res.status(303).set('Location', BASE + '/mfa?done=' +
          encodeURIComponent('Those codes were thrown away and never stored. ' +
                             'Whatever you had before is unchanged.')).end();
        return undefined;
      }

      // An `action` the schema allowed and this handler does not know is not
      // reachable from the form; it is redrawn rather than errored, for the
      // reason the sign-in screen falls through on an unknown action.
      log.debug('Leaving POST ' + BASE + '/mfa. No action.');
      errorCodes.mark(res, 'STS-PORTAL-0026');
      return self.send(res, 400, self.mfaPage(session, null,
        'Nothing was asked ' +
        'for.', await self.pendingEnrolmentFor(username, base)));
    });

    // -------------------------------------------------------------------------
    // GET /portal/signing-key — what you hold, and the button.
    // -------------------------------------------------------------------------
    app.get(BASE + '/signing-key', function (req, res) {
      log.debug('Entering GET ' + BASE + '/signing-key.');
      const session = self.requireSignIn(req, res, BASE + '/signing-key',
                                    accessGate.ACTION.READ);
      if (!session) return undefined;
      const asked = validation.check(req, 'query', PORTAL_QUERY);
      if (!asked.ok) {
        errorCodes.mark(res, self.innerCode(asked) || 'STS-PORTAL-0001');
        return self.refuseShape(res, asked);
      }
      log.debug('Leaving GET ' + BASE + '/signing-key.');
      return self.send(res, 200, self.signingKeyPage(
        session, asked.value.done || null, null, null, baseUrlOf(req)));
    });

    // -------------------------------------------------------------------------
    // POST /portal/signing-key — generate, or take it off.
    //
    // **`manage-own` FOR BOTH**, which is `/portal/mfa`'s rule and its reason:
    // a deployment that later lets a helpdesk role READ an account without
    // changing it must not have a door that mints a credential on the read side
    // of that line. Issuing is plainly a change, and so is taking one away.
    // -------------------------------------------------------------------------
    app.post(BASE + '/signing-key', async function (req, res) {
      log.debug('Entering POST ' + BASE + '/signing-key.');
      const session = self.requireSignIn(req, res, BASE + '/signing-key',
                                    accessGate.ACTION.MANAGE_OWN);
      if (!session) return undefined;
      // THE IDENTITY IS THE SESSION'S AND THERE IS NO PARAMETER FOR IT — the
      // rule at the top of this file. `SIGNING_KEY_FORM` carries no name for
      // the same reason, so this is two statements of one thing rather than a
      // check.
      const username = session.user.username;
      const base = baseUrlOf(req);
      const posted = validation.checkParsed(parseBody(req), 'body',
                                            SIGNING_KEY_FORM);
      if (!posted.ok) {
        errorCodes.mark(res, self.innerCode(posted) || 'STS-PORTAL-0001');
        return self.refuseShape(res, posted);
      }
      const body = posted.value;
      const action = String(body.action || '');
      const profile = self.signingKeyProfile(String(body.purpose || 'jwt'));

      const csrf = websecurity.checkCsrf(session.id, body);
      if (!csrf.ok) {
        log.warn('portal: a signing-key change for ' + username +
                 ' was refused on CSRF (' + csrf.reason + ').');
        audit.record({
          category: 'authentication', action: 'portal.signing-key.csrf',
          errorCode: self.innerCode(csrf) || 'STS-PORTAL-0017',
          actor: username, outcome: 'failure',
          summary: 'a signing key change was refused: ' + csrf.reason,
          detail: { address: websecurity.addressOf(req), what: action }
        });
        log.debug('Leaving POST ' + BASE + '/signing-key. CSRF.');
        errorCodes.mark(res, self.innerCode(csrf) || 'STS-PORTAL-0017');
        return self.send(res, 403, self.signingKeyPage(
          session, null, csrf.detail, null, base));
      }

      // -----------------------------------------------------------------------
      // A TLS CLIENT CERTIFICATE (2026-09-13): revoke one of yours.
      //
      // The serial comes from the form, and it is looked up among THIS PERSON'S
      // certificates in `tlsClient.revoke()` — one belonging to somebody else
      // matches nothing, which is `/portal/remove-key`'s arrangement. A
      // redirect, because nothing secret comes back.
      // -----------------------------------------------------------------------
      if (action === 'revoke-tls-client') {
        const revoked = tlsClient.revoke(undefined, username,
                                         String(body.serial || ''),
                                         body.reason);
        if (!revoked.ok) {
          log.debug('Leaving POST ' + BASE + '/signing-key. Not revoked.');
          errorCodes.mark(res, self.innerCode(revoked) || 'STS-PORTAL-0039');
          return self.send(res, 400, self.signingKeyPage(session, null,
            (revoked.errors || ['That certificate could not be revoked.'])[0],
            null, base));
        }
        audit.record({
          category: 'authentication', action: 'portal.tls-client.revoked',
          actor: username, outcome: 'success',
          summary: username + ' revoked their own TLS client certificate ' +
                   revoked.certificate.serialHex + ' (' + revoked.reason + ')',
          detail: { serialHex: revoked.certificate.serialHex,
                    label: revoked.certificate.label, reason: revoked.reason,
                    already: !!revoked.already,
                    address: websecurity.addressOf(req) }
        });
        log.info('portal: ' + username + ' revoked their TLS client ' +
                 'certificate ' + revoked.certificate.serialHex + ' (' +
                 revoked.reason + '). The TLS listeners refuse it from now ' +
                 'on.');
        log.debug('Leaving POST ' + BASE + '/signing-key. TLS client revoked.');
        res.status(303).set('Location', BASE + '/signing-key?done=' +
          encodeURIComponent('That TLS client certificate is revoked. A ' +
                             'browser presenting it is refused from now ' +
                             'on.')).end();
        return undefined;
      }

      // -----------------------------------------------------------------------
      // A TLS CLIENT CERTIFICATE: generate one, and answer with the files.
      //
      // **RENDERED AND NOT REDIRECTED**, for `generate`'s reason below: the
      // private key is in the response and nowhere else. The self-service
      // switch and both rate limits are the signing keys' own, checked in the
      // same order.
      // -----------------------------------------------------------------------
      if (action === 'generate-tls-client') {
        if (config.value('pki.personSelfService') === false) {
          log.debug('Leaving POST ' + BASE + '/signing-key. Self-service is ' +
                                             'off.');
          errorCodes.mark(res, 'STS-PORTAL-0028');
          return self.send(res, 403, self.signingKeyPage(session, null,
            'This service does not let people issue their own certificates. ' +
            'An administrator can issue one to you.', null, base));
        }
        const passwordSaid = tlsClient.pkcs12PasswordProblem(body.p12_password,
                                                             body.p12_confirm);
        if (passwordSaid) {
          log.debug('Leaving POST ' + BASE + '/signing-key. File password.');
          errorCodes.mark(res, 'STS-PORTAL-0040');
          return self.send(res, 400, self.signingKeyPage(
            session, null, passwordSaid, null, base));
        }
        const allowedTls = await websecurity.attemptShared('portal-signing-key',
                                                           req, username, {
          identity: config.value('pki.personSelfServicePerIdentity'),
          address: config.value('pki.personSelfServicePerAddress')
        });
        if (!allowedTls.ok) {
          log.debug('Leaving POST ' + BASE + '/signing-key. Rate limited.');
          errorCodes.mark(res, self.innerCode(allowedTls) || 'STS-PORTAL-0020');
          return self.send(res, 429, self.signingKeyPage(
            session, null, allowedTls.detail, null, base));
        }
        const made = await tlsClient.issue(undefined, {
          username: username,
          label: String(body.label || '').trim(),
          keyAlg: body.key_alg,
          email: self.mailOf(session)
        });
        if (!made.ok) {
          log.debug('Leaving POST ' + BASE + '/signing-key. Not issued.');
          errorCodes.mark(res, self.innerCode(made) || 'STS-PORTAL-0041');
          return self.send(res, 400, self.signingKeyPage(session, null,
            (made.errors || ['A TLS client certificate could not be ' +
                             'issued.'])[0],
            null, base));
        }
        let files;
        try {
          files = await tlsClient.bundle(made.issued, body.p12_password);
        } catch (e) {
          // THE CERTIFICATE EXISTS AND ITS KEY IS GONE. Revoked at once rather
          // than left valid in the register: a certificate nobody can ever
          // present is only a line on a list, and one nobody can revoke because
          // nobody knows its key was lost is worse.
          log.error(errorCodes.tag('STS-PORTAL-0042') + 'portal: a TLS ' +
                    'client certificate was issued to ' + username +
                    ' and its ' +
                    'files could not be built, so it was ' +
                    'revoked: ' + e.message);
          tlsClient.revoke(undefined, username, made.issued.serialHex,
                           'cessationOfOperation');
          errorCodes.mark(res, 'STS-PORTAL-0042');
          return self.send(res, 500, self.signingKeyPage(session, null,
            'The certificate could not be packaged for download, so it was ' +
            'revoked. Try again.', null, base));
        }
        audit.record({
          category: 'authentication', action: 'portal.tls-client.issued',
          actor: username, outcome: 'success',
          summary: username + ' issued themselves a TLS client certificate, ' +
                   'serial ' + made.issued.serialHex,
          detail: { serialHex: made.issued.serialHex, label: made.issued.label,
                    keyAlg: made.issued.keyAlg, notAfter: made.issued.notAfter,
                    realm: made.issued.scope,
                    address: websecurity.addressOf(req) }
        });
        log.info('portal: ' + username + ' issued themselves a TLS client ' +
                 'certificate, serial ' + made.issued.serialHex + ', valid ' +
                 'until ' + made.issued.notAfter +
                 '. The private key went out once in ' +
                 'the response and is not readable again.');
        log.debug('Leaving POST ' + BASE + '/signing-key. TLS client issued.');
        return self.send(res, 200, self.signingKeyPage(session, null, null, {
          kind: 'tls-client', issued: made.issued, files: files
        }, base));
      }

      if (action === 'remove') {
        // ONE PROFILE AT A TIME: taking the RFC 7522 key pair off leaves the
        // RFC 7523 one working, and the reverse.
        const removed = personAssertions.clear(username, profile.id,
          { initiatingEntity: 'user', via: 'portal' });
        if (!removed.ok) {
          log.debug('Leaving POST ' + BASE + '/signing-key. Nothing to ' +
                                             'remove.');
          errorCodes.mark(res, 'STS-PORTAL-0027');
          return self.send(res, 400, self.signingKeyPage(session, null,
            'You hold no ' + profile.rfc + ' signing key, so there was ' +
            'nothing to take off.', null, base));
        }
        audit.record({
          category: 'authentication', action: 'portal.signing-key.removed',
          actor: username, outcome: 'success',
          summary: username + ' took their own ' + profile.rfc + ' signing ' +
                   'key off',
          detail: { purpose: profile.id, attributes: removed.removed,
                    address: websecurity.addressOf(req) }
        });
        log.info('portal: ' + username + ' removed their ' + profile.rfc +
                 ' assertion signing key. Assertions signed with it are ' +
                 'refused from now on; the certificate itself is on no ' +
                 'revocation list.');
        log.debug('Leaving POST ' + BASE + '/signing-key. Removed.');
        res.status(303).set('Location', BASE + '/signing-key?done=' +
          encodeURIComponent('Your ' + profile.rfc + ' signing key is off. ' +
                             'Anything still signing with it will be refused ' +
                             'from now on.')).end();
        return undefined;
      }

      if (action === 'generate') {
        // **THE SETTING IS CHECKED AT THE DOOR AND NOT ONLY ON THE PAGE**,
        // which is `/portal/mfa`'s rule word for word: the page is markup and
        // this is the door, so a form posted by hand while
        // `pki.personSelfService` is off must not issue anything.
        if (config.value('pki.personSelfService') === false) {
          log.debug('Leaving POST ' + BASE + '/signing-key. Self-service is ' +
                                             'off.');
          errorCodes.mark(res, 'STS-PORTAL-0028');
          return self.send(res, 403, self.signingKeyPage(session, null,
            'This service does not let people issue their own signing keys. ' +
            'An administrator can issue one to you.', null, base));
        }
        // RATE LIMITED, and for a reason none of the other doors here has:
        // generating an RSA key pair is hundreds of milliseconds of CPU in a
        // process that answers every protocol in this service on one thread.
        // The limit is explicit rather than the shared default because what is
        // being protected is the SERVICE rather than an account — five is more
        // than anybody needs and far less than it takes to notice.
        //
        // **TWO SETTINGS SINCE 2026-09-12, AND THE DEFAULTS ARE THE FIVE IT
        // WAS.** The literal 5 applied to BOTH buckets, so everybody behind one
        // NAT or proxy shared five key generations a window between them. The
        // per-address number is its own row now so a deployment whose people
        // arrive from one address can raise it without raising what one person
        // may do.
        const allowed =
          await websecurity.attemptShared('portal-signing-key', req,
                                          username, {
            identity: config.value('pki.personSelfServicePerIdentity'),
            address: config.value('pki.personSelfServicePerAddress')
          });
        if (!allowed.ok) {
          log.debug('Leaving POST ' + BASE + '/signing-key. Rate limited.');
          errorCodes.mark(res, self.innerCode(allowed) || 'STS-PORTAL-0020');
          return self.send(res, 429, self.signingKeyPage(
            session, null, allowed.detail, null, base));

        }
        const issued = await pki.issueSigningKeyPair(undefined, {
          identifier: username,
          purpose: profile.id,
          // WHAT PUTS `urn:sts:person:<name>` IN THE CERTIFICATE, and the whole
          // reason this page may exist: it is what holds the key to asserting
          // about its own holder even when it is presented on its `x5c` alone,
          // with nothing on the entry left to consult.
          subjectKind: 'person',
          commonName: username,
          days: config.value('pki.leafLifetimeDays')
        });
        if (!issued.ok) {
          log.debug('Leaving POST ' + BASE + '/signing-key. The issue failed.');
          errorCodes.mark(res, self.innerCode(issued) || 'STS-PORTAL-0029');
          return self.send(res, 400, self.signingKeyPage(session, null,
            (issued.errors || ['A key pair could not be ' +
                               'issued.'])[0], null, base));
        }
        const record = issued.issued;
        const written = personAssertions.write(username, record,
          { purpose: profile.id, initiatingEntity: 'user', via: 'portal' });
        if (!written.ok) {
          // THE KEY PAIR IS GONE AND THE PAGE SAYS SO. `common/pki.js` hands
          // one over ONCE and keeps no copy, so a failed write is not a state
          // to retry from — showing the private key of a pair this service
          // cannot verify anything against would be worse than the refusal.
          log.error(errorCodes.tag('STS-PORTAL-0030') +
                    'portal: a signing key pair was issued to ' + username +
                    ' and could not be written: ' +
                    (written.errors || []).join(' '));
          errorCodes.mark(res, self.innerCode(written) || 'STS-PORTAL-0030');
          return self.send(res, 500, self.signingKeyPage(session, null,
            (written.errors || ['It could not be written to your entry.'])[0],
            null, base));
        }
        audit.record({
          category: 'authentication', action: 'portal.signing-key.issued',
          actor: username, outcome: 'success',
          summary: username + ' issued themselves an ' + profile.rfc +
                   ' signing key pair',
          detail: { purpose: profile.id, kid: record.kid,
                    thumbprint: record.certificateThumbprint,
                    notAfter: record.notAfter,
                    keyAlg: record.keyAlg,
                    address: websecurity.addressOf(req) }
        });
        log.info('portal: ' + username + ' issued themselves ' +
                                         'an ' + profile.rfc +
                 ' signing key pair, ' +
                 (profile.id === 'saml' ? 'thumbprint=' +
                  record.certificateThumbprint : 'kid=' + record.kid) +
                 ', valid until ' +
                 record.notAfter + '. The private half was shown to them ' +
                 'once and is not readable again.');
        log.debug('Leaving POST ' + BASE + '/signing-key. Issued and showing.');
        // **RENDERED AND NOT REDIRECTED**, which is the one place this endpoint
        // does that and is `generate-codes`' reason next door: a 303 has
        // nowhere to put a private key, and a query string would write it into
        // a browser history entry and every log between here and the person.
        return self.send(res, 200, self.signingKeyPage(session, null, null, {
          purpose: profile.id,
          privateKeyPem: record.privateKeyPem,
          certificatePem: record.certificatePem,
          kid: record.kid,
          thumbprint: record.certificateThumbprint,
          jwsAlg: record.jwsAlg,
          issuer: username
        }, base));
      }

      // An `action` the schema allowed and this handler does not know is not
      // reachable from the form; it is redrawn rather than errored, for the
      // reason the sign-in screen falls through on an unknown action.
      log.debug('Leaving POST ' + BASE + '/signing-key. No action.');
      errorCodes.mark(res, 'STS-PORTAL-0026');
      return self.send(res, 400, self.signingKeyPage(session, null, 'Nothing ' +
        'was asked for.',
                                           null, base));
    });

    // ASYNCHRONOUS SINCE 2026-09-14 (#46), for GET ACTIVATE's reason.
    app.post(BASE + '/password', async function (req, res) {
      log.debug('Entering POST ' + BASE + '/password.');
      const session = self.requireSignIn(req, res, BASE,
                                         accessGate.ACTION.MANAGE_OWN);
      if (!session) return undefined;
      const username = session.user.username;
      const posted = validation.checkParsed(parseBody(req), 'body',
                                            PASSWORD_FORM);
      if (!posted.ok) {
        errorCodes.mark(res, self.innerCode(posted) || 'STS-PORTAL-0001');
        return self.refuseShape(res, posted);
      }
      const body = posted.value;

      const csrf = websecurity.checkCsrf(session.id, body);
      if (!csrf.ok) {
        log.warn('portal: a password change for ' + username +
                 ' was refused on CSRF (' + csrf.reason + ').');
        audit.record({
          category: 'authentication', action: 'portal.password.csrf',
          errorCode: self.innerCode(csrf) || 'STS-PORTAL-0017',
          actor: username, outcome: 'failure',
          summary: 'a password change was refused: ' + csrf.reason,
          detail: { address: websecurity.addressOf(req) }
        });
        log.debug('Leaving POST ' + BASE + '/password. CSRF.');
        errorCodes.mark(res, self.innerCode(csrf) || 'STS-PORTAL-0017');
        return self.send(res, 403, self.passwordPage(session, null,
                                                     csrf.detail));
      }

      const allowed = await websecurity.attemptShared('password-change', req,
                                                      username);
      if (!allowed.ok) {
        log.debug('Leaving POST ' + BASE + '/password. Rate limited.');
        errorCodes.mark(res, self.innerCode(allowed) || 'STS-PORTAL-0019');
        return self.send(res, 429, self.passwordPage(session, null,
                                                     allowed.detail));
      }

      const current = String(body.current || '');
      const next = String(body.next || '');
      const confirm = String(body.confirm || '');

      // **RE-AUTHENTICATION.** A live session is not enough to change the
      // credential that session was created with — otherwise a browser left
      // open on a shared machine is an account takeover with no credential
      // needed.
      //
      // In DEVELOPMENT mode `verify()` accepts anything, so this is a formality
      // there — which is correct: development checks no password anywhere, and
      // a portal that was the one exception would be a surprise rather than a
      // control.
      const checked = credentials.verify(username, current,
                                         { via: 'the portal password change' });
      if (!checked.ok) {
        log.info('portal: a password change for ' + username +
                 ' was refused (' + checked.reason + ').');
        audit.record({
          category: 'authentication', action: 'portal.password.refused',
          errorCode: self.innerCode(checked) || 'STS-PORTAL-0031',
          actor: username, outcome: 'failure',
          summary: 'a password change was refused',
          detail: { reason: checked.reason,
                    address: websecurity.addressOf(req) }
        });
        log.debug('Leaving POST ' + BASE + '/password. Wrong current ' +
                                           'password.');
        errorCodes.mark(res, self.innerCode(checked) || 'STS-PORTAL-0031');
        return self.send(res, 400, self.passwordPage(session, null,
          'Your current password is not right.'));
      }
      if (!next || next !== confirm) {
        errorCodes.mark(res, 'STS-PORTAL-0032');
        return self.send(res, 400, self.passwordPage(session, null,
          next ? 'The two new passwords do not match.' : 'Give a new ' +
            'password.'));
      }
      const set = credentials.setPassword(username, next);
      if (!set.ok) {
        errorCodes.mark(res, self.innerCode(set) || 'STS-PORTAL-0008');
        return self.send(res, 400, self.passwordPage(session, null,
          (set.errors || ['The password could not be changed.'])[0]));
      }
      await websecurity.succeededShared('password-change', req, username);
      audit.record({
        category: 'authentication', action: 'portal.password.changed',
        actor: username, outcome: 'success',
        summary: username + ' changed their own password',
        detail: { address: websecurity.addressOf(req) }
      });
      log.info('portal: ' + username + ' changed their own password.');
      // CAEP credential-change (#145), as the console's set-password sends.
      self.deps.accountSignals.credentialChanged({ username: username,
        credentialType: 'password', changeType: 'update',
        initiatingEntity: 'user', via: 'portal',
        reasonAdmin: username + ' changed their own password.',
        reasonUser: 'You changed your password.' });
      log.debug('Leaving POST ' + BASE + '/password. Changed.');
      // BACK TO THE PAGE IT WAS POSTED FROM, and not to the overview. It used
      // to be the overview because the form was on it; now that the form has a
      // page, a redirect anywhere else would answer "did that work?" by moving
      // the reader somewhere the answer is not.
      res.status(303).set('Location', BASE + '/password?done=' +
        encodeURIComponent('Your password is changed.')).end();
      return undefined;
    });

    // =========================================================================
    // POST /portal/keys — BEGIN, FINISH OR CANCEL A REGISTRATION (2026-09-10).
    //
    // The door `enrolBlock()` argues. Three actions and one page, the shape
    // `/portal/mfa` already has for the authenticator app, because it is the
    // same two-step question asked about the other mechanism.
    //
    // **IT DOES NOT SIGN ANYBODY IN AND IT DOES NOT TOUCH THE SESSION.** This
    // is a person who is ALREADY signed in adding a credential to their own
    // account, which is the ordinary WebAuthn registration flow and is what
    // makes it different from `/authn/webauthn` — that page is a step IN a
    // sign-in and mints a session at the end of it.
    //
    // **THE USERNAME COMES FROM THE SESSION AND NEVER FROM THE BODY**, which is
    // this directory's A01 rule and the one thing about this handler that is
    // not negotiable: a key enrolled for a name in a request body would be a
    // signed-in person putting their own authenticator on somebody else's
    // account.
    // =========================================================================
    app.post(BASE + '/keys', function (req, res) {
      log.debug('Entering POST ' + BASE + '/keys.');
      const session = self.requireSignIn(req, res, BASE + '/keys',
                                    accessGate.ACTION.MANAGE_OWN);
      if (!session) {
        log.debug('Leaving POST ' + BASE +
                  '/keys. Not signed in, or not permitted.');
        return undefined;
      }
      const username = session.user.username;
      const base = baseUrlOf(req);
      const posted = validation.checkParsed(parseBody(req), 'body',
                                            ENROL_KEY_FORM);
      if (!posted.ok) {
        errorCodes.mark(res, self.innerCode(posted) || 'STS-PORTAL-0001');
        return self.refuseShape(res, posted);
      }
      const body = posted.value;

      const csrf = websecurity.checkCsrf(session.id, body);
      if (!csrf.ok) {
        log.debug('Leaving POST ' + BASE + '/keys. CSRF.');
        errorCodes.mark(res, self.innerCode(csrf) || 'STS-PORTAL-0017');
        return self.sendKeysPage(res, 403, self.keysPage(session, null,
                                                         csrf.detail, base));
      }
      const action = String(body.action || '');

      if (action === 'cancel') {
        credentials.abandonKeyEnrolment(username);
        log.debug('Leaving POST ' + BASE + '/keys. Abandoned.');
        res.status(303).set('Location', BASE + '/keys').end();
        return undefined;
      }

      if (action === 'begin') {
        // THE POLICY IS CHECKED AT THE DOOR AND NOT ONLY ON THE PAGE, which is
        // `authn.js`'s rule about the anonymous button and `/portal/mfa`'s
        // about `totp.enabled`: the page is markup and this is the door, so a
        // form posted by hand while `webauthn.primaryAllowed` is off must not
        // arm a ceremony that `addKey()` would then refuse after somebody had
        // touched their key. `beginKeyEnrolment()` makes every one of those
        // checks.
        const begun = credentials.beginKeyEnrolment(username, {
          role: String(body.role || 'mfa'), label: String(body.label || '')
        });
        if (!begun.ok) {
          log.debug('Leaving POST ' + BASE + '/keys. Refused to start.');
          errorCodes.mark(res, self.innerCode(begun) || 'STS-PORTAL-0033');
          return self.sendKeysPage(res, 400, self.keysPage(session, null,
            (begun.errors || ['The enrolment could not be ' +
                              'started.'])[0], base));
        }
        audit.record({
          category: 'authentication', action: 'portal.key.started',
          actor: username, outcome: 'success',
          summary: username + ' started enrolling a security key',
          detail: { role: begun.role, excluded: begun.exclude.length,
                    address: websecurity.addressOf(req) }
        });
        log.debug('Leaving POST ' + BASE + '/keys. Challenge minted and held.');
        // REDIRECT AND NOT A RENDER, for `/portal/mfa`'s reason: a rendered
        // response to a POST is one the browser offers to re-submit, and
        // re-submitting `begin` would mint a SECOND challenge under the
        // ceremony the person is in the middle of.
        res.status(303).set('Location', BASE + '/keys').end();
        return undefined;
      }

      if (action === 'finish') {
        let credential = null;
        try {
          credential = JSON.parse(String(body.credential || 'null'));
        } catch (e) {
          log.debug("Caught in a callback in module scope: " +
                    ((e && e.message) || e));
          // Not JSON. That is the real button underneath the script being
          // pressed, or a hand-made POST; either way the sentence below is the
          // right answer and a parse error is not.
          credential = null;
        }
        if (!credential) {
          log.debug('Leaving POST ' + BASE + '/keys. No ceremony ran.');
          errorCodes.mark(res, 'STS-PORTAL-0034');
          return self.sendKeysPage(res, 400, self.keysPage(session, null,
            'Your browser did not run the ceremony, so there is nothing to ' +
            'register. This page needs JavaScript for that one step — a ' +
            'security key is created by the browser and there is no form ' +
            'that can do it. The rest of this portal runs no script at ' +
            'all.', base));
        }
        // THE SAME TWO ADDRESS RULES THE SIGN-IN SCREEN APPLIES (2026-09-12):
        // an RP ID that does not fit is refused in product mode rather than
        // replaced by the request's host, and `webauthn.allowedOrigins` decides
        // the origin where it is set. Asked of `authn.js` so the two ceremonies
        // cannot differ.
        const rpRefusal = authn.rpIdProblem(base);
        if (rpRefusal) {
          log.debug('Leaving POST ' + BASE + '/keys. The RP ID does not fit.');
          errorCodes.mark(res, 'STS-PORTAL-0035');
          return self.sendKeysPage(res, 400, self.keysPage(session, null,
                                                           rpRefusal, base));
        }
        // A PROMISE SINCE 2026-09-14: the write claims the credential id across
        // nodes first (`credentials.addKeyClaimed()`), so two posts of one
        // attestation cannot leave two rows for one key.
        credentials.confirmKeyEnrolment(username,
          String(body.enrolment_id || ''), credential,
          { origin: authn.expectedOriginFor(base, credential),
            rpId: authn.rpIdOf(base) }).then(function (done) {
          if (!done.ok) {
            audit.record({
              category: 'authentication', action: 'portal.key.refused',
              errorCode: self.innerCode(done) || 'STS-PORTAL-0036',
              actor: username, outcome: 'failure',
              summary: 'a security key enrolment was not completed ' +
                       'for ' + username,
              detail: { reason: done.reason || '',
                        address: websecurity.addressOf(req) }
            });
            log.debug('Leaving POST ' + BASE + '/keys. ' +
                                               'Refused: ' + done.reason);
            errorCodes.mark(res, self.innerCode(done) || 'STS-PORTAL-0036');
            return self.sendKeysPage(res, 400, self.keysPage(session, null,
              (done.errors || ['The security key could not be registered.'])[0],
              base));
          }
          // CAEP credential-change (#145), the key described by what its
          // enrolment recorded: attachment and AAGUID.
          const enrolled = credentials.keysOf(username).filter(function (one) {
            return one.credentialId === String(done.credentialId || '');
          })[0] || null;
          self.deps.accountSignals.credentialChanged({ username: username,
            credentialType: self.deps.accountSignals.keyCredentialType(
              enrolled),
            fido2Aaguid: String((enrolled && enrolled.aaguid) || ''),
            friendlyName: String((enrolled && enrolled.label) || ''),
            changeType: 'create', initiatingEntity: 'user', via: 'portal',
            reasonAdmin: username + ' enrolled a security key.',
            reasonUser: 'You enrolled a security key.' });
          audit.record({
            category: 'authentication', action: 'portal.key.enrolled',
            actor: username, outcome: 'success',
            summary: username + ' enrolled a security key as a ' + done.role +
                     ' credential',
            detail: { role: done.role, held: done.held,
                      address: websecurity.addressOf(req) }
          });
          log.info('portal: ' + username + ' enrolled a "' + done.role +
                   '" security key and now holds ' + done.held + '.');
          res.status(303).set('Location', BASE + '/keys?done=' +
            encodeURIComponent(done.held > 1
              ? 'That key is registered. You hold ' + done.held +
                ' — if one is lost the others still sign you in.'
              : 'That key is registered. Add a second one on a different ' +
                'device so that losing this one is not a locked ' +
                'account.')).end();
          return undefined;
        }).catch(function (e) {
          log.debug('Caught in POST ' + BASE + '/keys: ' +
                    ((e && e.message) || e));
          // Express 4 does not look at a returned promise; a throw here must
          // still answer the page.
          errorCodes.mark(res, 'STS-PORTAL-0036');
          self.sendKeysPage(res, 500, self.keysPage(session, null,
            'The security key could not be registered. Try again.', base));
        });
        return undefined;
      }

      log.debug('Leaving POST ' + BASE + '/keys. Unknown action.');
      errorCodes.mark(res, 'STS-PORTAL-0026');
      return self.sendKeysPage(res, 400, self.keysPage(session, null,
        'Unknown action "' + self.esc(action) + '". There are three: begin, ' +
        'finish and cancel.', base));
    });

    app.post(BASE + '/remove-key', function (req, res) {
      log.debug('Entering POST ' + BASE + '/remove-key.');
      const session = self.requireSignIn(req, res, BASE,
                                         accessGate.ACTION.MANAGE_OWN);
      if (!session) return undefined;
      const username = session.user.username;
      const posted = validation.checkParsed(parseBody(req), 'body',
                                            REMOVE_KEY_FORM);
      if (!posted.ok) {
        errorCodes.mark(res, self.innerCode(posted) || 'STS-PORTAL-0001');
        return self.refuseShape(res, posted);
      }
      const body = posted.value;

      const csrf = websecurity.checkCsrf(session.id, body);
      if (!csrf.ok) {
        log.debug('Leaving POST ' + BASE + '/remove-key. CSRF.');
        errorCodes.mark(res, self.innerCode(csrf) || 'STS-PORTAL-0017');
        return self.send(res, 403, self.keysPage(session, null, csrf.detail,
                                                 baseUrlOf(req)));
      }
      // THE CREDENTIAL ID COMES FROM THE BODY AND THE USERNAME DOES NOT, which
      // is the distinction that keeps this safe: `removeKey()` looks the id up
      // among THIS PERSON'S keys, so an id belonging to somebody else matches
      // nothing. An implementation that took both from the request would be the
      // A01 vulnerability this file exists to avoid.
      // The key as it was, read first: the event describes what was removed.
      const going = credentials.keysOf(username).filter(function (one) {
        return one.credentialId === String(body.credentialId || '');
      })[0] || null;
      const removed = credentials.removeKey(username,
                                            String(body.credentialId || ''));
      if (!removed.ok) {
        log.debug('Leaving POST ' + BASE + '/remove-key. Refused.');
        errorCodes.mark(res, self.innerCode(removed) || 'STS-PORTAL-0037');
        return self.send(res, 400, self.keysPage(session, null,
          (removed.errors || ['The key could not be removed.'])[0],
          baseUrlOf(req)));
      }
      self.deps.accountSignals.credentialChanged({ username: username,
        credentialType: self.deps.accountSignals.keyCredentialType(going),
        fido2Aaguid: String((going && going.aaguid) || ''),
        friendlyName: String((going && going.label) || ''),
        changeType: 'delete', initiatingEntity: 'user', via: 'portal',
        reasonAdmin: username + ' removed a security key.',
        reasonUser: 'You removed a security key.' });
      audit.record({
        category: 'authentication', action: 'portal.key.removed',
        actor: username, outcome: 'success',
        summary: username + ' removed one of their security keys',
        detail: { remaining: removed.remaining,
                  address: websecurity.addressOf(req) }
      });
      log.debug('Leaving POST ' + BASE + '/remove-key. Removed.');
      res.status(303).set('Location', BASE + '/keys?done=' +
        encodeURIComponent('That security key is removed.')).end();
      return undefined;
    });

    // =========================================================================
    // SIGNING OUT (2026-09-06). The other end of the callback above.
    //
    // **IT ENDS TWO SESSIONS**, for the reason the admin console's own sign-out
    // gives at length and which is the same here: this portal is a relying
    // party with a session of its own, derived from the SIGN-ON session the
    // person holds with this service. Ending only the portal's would be a Sign
    // out button that does not sign anybody out — the next request to /portal
    // runs the code flow, meets the sign-on session that is still live, and
    // comes straight back in with nothing to type.
    //
    // **IT IS NOT `/logout`, AND THE PAGE AT THE FOOT OF THE ACCOUNT PAGE STILL
    // IS.** That endpoint ends everything this identity holds in every protocol
    // — tokens, tickets, offers, binds — and it stays exactly where it was,
    // under a heading that now says which of the two reaches further. This one
    // is what a Sign out button in the corner of a page means everywhere else:
    // this browser is done.
    //
    // **NO `requireSignIn()`**, and that is deliberate rather than an omission.
    // That function REDIRECTS a person with no session into the authorization
    // code flow, which for a sign-out would send somebody who is already signed
    // out off to sign in — the exact opposite of what they pressed. A sign-out
    // asked of a browser with no session is not an error either; it is a page
    // saying they are signed out, which is true.
    // =========================================================================
    app.post(BASE + '/signout', function (req, res) {
      log.debug('Entering POST ' + BASE + '/signout.');
      const session = oidcRp.sessionFor(req, 'portal');
      if (!session) {
        // Nothing to end and nothing to check: there is no session to bind a
        // CSRF token to, and refusing here would only ever refuse somebody who
        // is already in the state they were asking for.
        log.debug('Leaving POST ' + BASE + '/signout. There was no session.');
        return self.send(res, 200, self.page('Signed out',
          '<div class="card"><h1>You are signed out</h1><p ' +
          'class="note">There was no portal session on this browser to ' +
          'end.</p><p><a href="' + self.esc(self.signInHref()) +
          '">Sign in</a></p></div>'));
      }
      const username = session.user.username;
      const body = parseBody(req);
      const csrf = websecurity.checkCsrf(session.id, body);
      if (!csrf.ok) {
        // REFUSED AND NOT PERFORMED, which is worth the line: a sign-out fired
        // from another site is the classic "harmless" CSRF that is not —
        // somebody's session ended under them, repeatedly, with no way to stay
        // signed in.
        log.warn('portal: a sign-out for ' + username +
                 ' was refused on CSRF (' + csrf.reason + ').');
        audit.record({
          category: 'authentication', action: 'portal.signout.csrf',
          errorCode: self.innerCode(csrf) || 'STS-PORTAL-0017',
          actor: username, outcome: 'failure',
          summary: 'a sign-out was refused: ' + csrf.reason,
          detail: { address: websecurity.addressOf(req) }
        });
        log.debug('Leaving POST ' + BASE + '/signout. CSRF.');
        errorCodes.mark(res, self.innerCode(csrf) || 'STS-PORTAL-0017');
        return self.send(res, 403, self.overviewPage(session, null,
                                                     csrf.detail));

      }
      const parent = String(session.derivedFrom || '');
      oidcRp.endSessionFor(req, res, 'portal', 'the Sign out button on the ' +
                                               'user portal');
      const signOnEnded = parent
        ? !!authn.endSessionById(parent, 'the Sign out button on the user ' +
                                         'portal')
        : false;
      // AND THE SIGN-ON COOKIE. `endSessionById()` takes no response — it is
      // how /logout ends sessions that are not the caller's — so the cookie
      // naming it has to be cleared here, or the browser goes on presenting a
      // session this service no longer holds.
      if (signOnEnded) {
        authn.clearSessionCookie(res);
      }
      audit.record({
        category: 'authentication', action: 'portal.signout',
        actor: username, outcome: 'success',
        summary: username + ' signed out of the user portal' +
                 (signOnEnded ? ', and of the sign-on session behind it' : ''),
        detail: { portalSession: session.id, signOnSession: parent || '(none)',
                  signOnEnded: signOnEnded,
                  address: websecurity.addressOf(req) }
      });
      log.info('portal: ' + username + ' signed out. The portal session ' +
               'is gone' +
               (signOnEnded ?
                ' and so is the sign-on session behind it (' + parent +
                '), with every session derived from it.'
                : '; there was no sign-on session left to end.'));
      log.debug('Leaving POST ' + BASE + '/signout. Signed out.');
      return self.send(res, 200, self.page('Signed out',
        '<div class="card"><h1>You are signed out</h1>' +
        '<div class="ok">Your portal session has ended' +
        (signOnEnded
          ? ', and so has the sign-on session it was built on — so anything ' +
            'else you were signed in to through it is signed out too.'
          : '. There was no sign-on session left behind it to ' +
            'end.') + '</div><p ' +
        'class="note">Signing out of the portal alone would not have signed ' +
        'you out: this portal is an ordinary OpenID Connect client of this ' +
        'service (<code>sts-user-portal</code>), so the next page would have ' +
        'run the sign-in flow again, met the sign-on session and let you ' +
        'back in with nothing to type.</p><p class="note">Tokens, tickets ' +
        'and other credentials already issued to applications are untouched. ' +
        '<a href="/logout">/logout</a> lists all of them and ends what you ' +
        'choose.</p><p><a href="' + self.esc(self.signInHref()) + '">Sign in ' +
        'again</a></p></div>'));
    });
    log.debug("Leaving Portal.registerRoutes().");
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds
// no instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` when the module loads (see
// `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<Portal>(
  'portal/portal',
  () => new Portal(Portal.defaultDeps()),
  null,
  helpers.log);

// ROUTES ARE REGISTERED BY THE COMPOSITION ROOT (#50, R1): requiring this
// module no longer registers anything. `common/protocol_stack.ts` calls the
// exported `registerRoutes(app)` at the point in the route order where
// requiring this module used to register them.
// Here that is the portal's pages, then /portal/certificates.

helpers.log.info('The User Portal is at ' + BASE + ': a person\'s own ' +
                 'account, in ' + NAV_PAGES.length + ' pages behind a ' +
                 'navigation column of its own — what this identity ' +
                 'provider knows about them, WHICH APPLICATIONS THEY MAY ' +
                 'SIGN IN TO (decided by the same issuance policy the ' +
                 'protocol endpoints ask), their password, their security ' +
                 'keys and their AUTHENTICATOR APP. ' + ACTIVATE + ' is the ' +
                 'unauthenticated half, where somebody provisioned through ' +
                 '/admin-api or SCIM spends a single-use activation link to ' +
                 'set up a credential. Every form carries a CSRF token, ' +
                 'every credential endpoint is rate limited, and no route ' +
                 'here takes an identity from the request.');

// ---------------------------------------------------------------------------
// /portal/certificates (2026-09-13), registered by the exported
// `registerRoutes(app)` below — after every other page of the column, so the
// route order is the column's — by the file beside this one, which is handed
// the pieces that make a page a portal page. See its header for why this is a
// `register()` rather than a require that registers at its top level.
// ---------------------------------------------------------------------------
const portalCertificates = require('./portal_certificates');

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

export = {
  registerRoutes: (target: any): void => {
    slot.get().registerRoutes(target);
    portalCertificates.register({
      app: target, BASE: BASE, log: helpers.log,
      esc: slot.forward('esc'),
      shell: slot.forward('shell'),
      send: slot.forward('send'),
      requireSignIn: slot.forward('requireSignIn'),
      refuseShape: slot.forward('refuseShape'),
      innerCode: slot.forward('innerCode'),
      baseUrlOf: helpers.baseUrlOf, parseBody: helpers.parseBody,
      validation: validation, websecurity: websecurity,
      accessGate: accessGate,
      audit: audit, errorCodes: errorCodes, config: config
    });
  },
  Portal: Portal,
  installInstance: (instance: Portal): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  BASE: Portal.BASE,
  ACTIVATE: Portal.ACTIVATE,
  // Filled by `ldap/ldap_server.js` at its require time — see the block above
  // it for why this is a slot rather than a require.
  setDirectory: slot.forward('setDirectory'),
  // For sts_metadata.js and the tests.
  paths: slot.forward('paths')
};
