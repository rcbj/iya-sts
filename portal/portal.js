'use strict';
//
// File: portal.js
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
// `paths()` reports it to `sts_metadata.js`, so there is one copy of it.
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
//                                       disagree. See applicationsFor().
//   `/portal/password`                  AUTHENTICATED. The form, and the POST
//                                       that answers it, on one path.
//   `/portal/keys`                      AUTHENTICATED. Their security keys.
//
// ---------------------------------------------------------------------------
// IT IS A SEPARATE APPLICATION FROM THE ADMIN CONSOLE AND SHARES NOTHING BUT
// THE SESSION.
//
// Not the shell, not the navigation, not the gate. That is deliberate: the
// console's `respond()` draws a sidebar of forty administrative pages and its
// gate answers "does this person hold Admin Read" — neither of which is
// anything a person managing their own account should meet. **What they share
// is `authn.js`'s session**, because there is one answer in this service to
// "who is this browser" and a second would be the thing that eventually
// disagrees.
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
//                         rest — `common/credentials.js`
//   A03 injection         every value through `esc()`; this service builds no
//                         SQL from user input anywhere
//   A04 insecure design   rate limiting on activation and password change —
//                         `common/websecurity.js`
//   A05 misconfiguration  the CSP `app.js` sets on every response, including
//                         `script-src 'none'` and `frame-ancestors 'none'`
//   A07 auth failures     CSRF tokens on every POST here, session replaced on
//                         sign-in, and no message that distinguishes "no such
//                         person" from "wrong credential"
//   A09 logging           every act audited through `audit.js`
//
// A LIBRARY? No — it registers routes (rule 1), so its place in the require
// order is a place. It must come AFTER `authn.js`, whose session it reads.
// ---------------------------------------------------------------------------

const app = require('../common/app');
const helpers = require('../common/helpers');
const { log, parseBody, baseUrlOf } = helpers;
const config = require('../common/config');
const mode = require('../common/mode');
const credentials = require('../common/credentials');
const websecurity = require('../common/websecurity');
const authn = require('../authn/authn');
// THE RELYING PARTY (2026-09-06). This portal authenticates through the
// AUTHORIZATION CODE FLOW against this service's own authorization server now,
// as the registered client `sts-user-portal`, rather than by asking `authn.js`
// for a screen and reading the session that screen minted. `common/oidc_rp.js`
// runs the flow and argues it; the section below is what changed here.
const oidcRp = require('../common/oidc_rp');
// The access-control gate. A LEAF (rule 3), armed by xacml/xacml_access_pep.js
// at 23c — before that line every check is allowed, which is what a process
// without the XACML family does.
const accessGate = require('../common/access_gate');
const audit = require('../common/audit');

// The input validator. A LEAF (rule 3): it registers no route and requires only
// `config`, `bunyan` and zod, so it closes no cycle here and moves nothing.
const validation = require('../common/validation');
const vt = validation.types;
const vz = validation.z;
const stats = require('../common/admin_stats');

// ---------------------------------------------------------------------------
// THE REGISTRY AND THE ISSUANCE GATE, for `/portal/applications` (2026-09-06).
//
// Both are LIBRARIES (rule 3) and neither can move a route or close a cycle
// here: `common/applications.js` registers nothing — `admin-ui/admin.js` and
// `ldap/ldap_server.js` draw its pages — and `common/issuance_gate.js` requires
// `helpers` and `config` and nothing else, which is the whole point of it being
// a leaf. Both are already loaded by `oauth-oidc/oauth2.js` at 9, four lines
// above this module in `server.js`, so these two requires are cache hits.
//
// **THE GATE IS ASKED THE SAME QUESTION THE NINE ISSUANCE SITES ASK.** That is
// the property that makes the page worth having: a portal that worked out for
// itself which applications somebody may reach would be a SECOND
// implementation of the rule, and the first thing to disagree with the
// enforcement it is describing. See `applicationsFor()` below.
const applications = require('../common/applications');
const gate = require('../common/issuance_gate');
// THE VERSION, M.N.O, at the foot of every page here. A LEAF (rule 3):
// registers nothing and requires nothing from this repository. Read once at
// require time — it cannot change while the process runs. See
// common/version.js.
const version = require('../common/version');
const APP_VERSION = version.load();
const APP_BUILD_INFO = version.buildInfo(APP_VERSION);

const BASE = '/portal';
const ACTIVATE = BASE + '/activate';

// Everything drawn here goes through it. The console has its own; this is a
// separate application and shares no markup with it.
function esc(value) {
  return String(value === undefined || value === null ? '' : value)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

const CSS =
  'body{font-family:system-ui,-apple-system,"Segoe UI",Arial,sans-serif;' +
  'background:#f4f4f7;margin:0;padding:2rem 1rem;color:#222;line-height:1.5}' +
  '.wrap{max-width:720px;margin:0 auto}' +
  '.card{background:#fff;border:1px solid #d5d5dd;border-radius:10px;' +
  'padding:24px 28px;margin-bottom:18px;box-shadow:0 2px 10px rgba(0,0,0,.04)}' +
  'h1{font-size:1.4em;margin:0 0 4px}h2{font-size:1.05em;margin:0 0 12px}' +
  // The heading and its one control on the same line. `align-items:start` and
  // not `center`: the button is a small box beside a large heading and centring
  // it drags it down past the heading's baseline. The form's margin is reset
  // because `button` carries a top margin of its own for the stacked forms
  // below, which is right there and wrong here.
  '.pagehead{display:flex;gap:12px;align-items:start;' +
  'justify-content:space-between;flex-wrap:wrap}' +
  '.pagehead h1{margin:0}' +
  '.pagehead form{margin:0}.pagehead button{margin-top:0}' +
  'p.sub{color:#666;font-size:.9em;margin:0 0 18px}' +
  'label{display:block;font-size:.85em;font-weight:600;margin:12px 0 4px}' +
  'input[type=text],input[type=password]{width:100%;padding:9px 10px;' +
  'border:1px solid #c9c9d2;border-radius:6px;font-size:1em;box-sizing:border-box}' +
  'button{margin-top:14px;padding:9px 16px;border:0;border-radius:6px;' +
  'background:#2c5cc5;color:#fff;font-size:.95em;cursor:pointer}' +
  'button.danger{background:#b00020}button.secondary{background:#5a5a68}' +
  'table{border-collapse:collapse;width:100%;font-size:.9em}' +
  'th,td{text-align:left;padding:7px 10px;border-bottom:1px solid #e6e6ec}' +
  'th{color:#555;font-weight:600;width:34%}' +
  '.err{background:#fdecef;border:1px solid #f5c2cb;color:#8a1027;' +
  'padding:10px 12px;border-radius:6px;margin-bottom:14px;font-size:.9em}' +
  '.ok{background:#eaf6ec;border:1px solid #bfe3c6;color:#1d5b2a;' +
  'padding:10px 12px;border-radius:6px;margin-bottom:14px;font-size:.9em}' +
  '.note{color:#555;font-size:.85em;margin:10px 0 0}' +
  'code{background:#f0f0f5;padding:1px 5px;border-radius:4px;font-size:.9em}' +
  // -------------------------------------------------------------------------
  // THE TWO-COLUMN SHELL AND ITS NAVIGATION (2026-09-06). Its own rules and
  // its own palette: the console's sidebar is #12107c and forty pages long,
  // this one is the portal's blue and has four, and the two files sharing a
  // stylesheet is the thing this application deliberately does not do.
  //
  // `.side` is STICKY and has no `overflow-y` of its own, which is the one
  // difference from the console's worth stating rather than leaving as a
  // divergence somebody 'fixes'. That console scrolls its own nav because the
  // list is longer than a screen; four items are not, and a scroll container
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
  '.navsec.open{border-left:3px solid #2c5cc5;margin-left:-14px;padding-left:11px}' +
  '.navsec.open .navhead{color:#2c5cc5}' +
  'nav a,nav .here{display:block;padding:4px 7px;border-radius:5px;' +
  'text-decoration:none;color:#2c5cc5;font-size:.9em}' +
  'nav a:hover{background:#eef2fb}' +
  'nav .here{font-weight:700;color:#fff;background:#2c5cc5}' +
  '.who{color:#666;font-size:.85em;margin:3px 0 0}' +
  // A HEADER TABLE RATHER THAN A LABEL COLUMN. `th` above is 34% wide because
  // every table in this application until now was two columns of name and
  // value; the applications list is four columns with a heading ROW, where a
  // third of the width for the first cell is simply wrong.
  '.grid th{width:auto;color:#555}' +
  '.grid td strong{display:block}' +
  // A BLOCK, because two of them follow the application's name in one cell —
  // the identifier and the description — and inline they run together into
  // one line that reads as a single fact.
  '.ident{display:block;color:#666;font-size:.85em}' +
  '.tag{display:inline-block;background:#eef2fb;border:1px solid #d3ddf4;' +
  'color:#26417d;border-radius:4px;padding:0 6px;margin:0 4px 3px 0;font-size:.8em}' +
  '.pagenav{margin:14px 0 0;font-size:.85em}' +
  '.pagenav a,.pagenav span{display:inline-block;padding:3px 9px;' +
  'border:1px solid #d5d5dd;border-radius:5px;margin-right:6px;' +
  'text-decoration:none;color:#2c5cc5;background:#fff}' +
  '.pagenav .here{background:#2c5cc5;border-color:#2c5cc5;color:#fff;font-weight:700}' +
  '.pagenav .off{color:#9a9aa6;background:#f4f4f7}' +
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
  '.ver code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}';

function page(title, inner, wide) {
  return '<!DOCTYPE html>\n<html lang="en"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width,initial-scale=1">' +
    '<title>' + esc(title) + ' — mock STS</title><style>' + CSS +
    '</style></head><body><div class="wrap' + (wide ? ' wide' : '') + '">' +
    inner +
    // WHICH BUILD THIS IS, on every page of this application including the two
    // that nobody is signed in for — the activation form and the signed-out
    // pages. It is in `page()` and not in `shell()` for exactly that reason:
    // the surfaces a person reaches when something has gone wrong are the ones
    // where "which build were you on" is most likely to be asked, and those are
    // precisely the pages `shell()` never draws.
    //
    // The provenance is in the tooltip rather than on the line. This is a
    // person's own account, not a console: the number is enough to quote, and
    // the build instant and commit are for whoever they quote it to.
    '<p class="ver" title="' + esc(APP_BUILD_INFO) + '">mock-sts <code>' +
    esc(APP_VERSION.version) + '</code></p>' +
    '</div></body></html>\n';
}

function send(res, status, html) {
  // `no-store` on every page: this one draws a person's own account details and
  // is reached from a shared browser as often as not.
  res.status(status).set('Cache-Control', 'no-store').type('html').send(html);
}

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
        heading: 'Applications you can sign in to' }
    ] },
  { title: 'How you sign in',
    what: 'The credentials on your own entry, one page each.',
    items: [
      { path: BASE + '/password', label: 'Password',
        heading: 'Change your password' },
      { path: BASE + '/keys', label: 'Security keys',
        heading: 'Your security keys' }
    ] }
];

const NAV_PAGES = NAV.reduce(function (all, section) {
  return all.concat(section.items);
}, []);

// The page's own title, read off the table rather than passed in at the call
// site: a renamed page would otherwise be renamed in the column and not in the
// heading over it, and the two would be right for exactly as long as nobody
// looked.
function headingFor(active) {
  const row = NAV_PAGES.filter(function (one) { return one.path === active; })[0];
  return row ? row.heading : 'Your account';
}

function navBar(active) {
  log.debug('Entering navBar(). active=' + active);
  const html = '<nav aria-label="Account pages">' +
    NAV.map(function (section) {
      const here = section.items.filter(function (item) {
        return item.path === active;
      }).length > 0;
      return '<div class="navsec' + (here ? ' open' : '') + '">' +
        '<p class="navhead" title="' + esc(section.what) + '">' +
        esc(section.title) + '</p><ul>' +
        section.items.map(function (item) {
          if (item.path === active) {
            // A SPAN AND NOT A LINK, and no `autofocus` on it — see the
            // stylesheet, where the console's reason for having one and this
            // application's reason for not is argued. `aria-current` is what
            // tells a screen reader the same thing the colour tells everybody
            // else.
            return '<li><span class="here" aria-current="page">' +
                   esc(item.label) + '</span></li>';
          }
          return '<li><a href="' + esc(item.path) + '">' + esc(item.label) +
                 '</a></li>';
        }).join('') + '</ul></div>';
    }).join('') + '</nav>';
  log.debug('Leaving navBar(). ' + NAV.length + ' section(s).');
  return html;
}

// ---------------------------------------------------------------------------
// ONE SIGNED-IN PAGE: the header, the column, and this page's cards.
//
// **THE SIGN OUT BUTTON IS IN THE HEADER AND SO IS ON EVERY PAGE.** It was in
// the corner of the one page there was; it is in the corner of all of them now,
// which is the same decision rather than a new one — a person who wants out
// should not have to find the page it lives on first.
//
// `message` and `error` are drawn HERE rather than by each page, because every
// page in this application can be reached carrying either: a redirect after a
// successful write says so with `?done=`, and a refused write re-draws the page
// it was posted from with the reason on it.
// ---------------------------------------------------------------------------
function shell(active, session, message, error, cards) {
  log.debug('Entering shell(). active=' + active);
  const heading = headingFor(active);
  const csrf = websecurity.field(session.id);
  const html = page(heading,
    // THE HEADING AND THE SIGN OUT BUTTON IN ONE ROW, so that the control is
    // where a person looks for it — the top corner of the page they are on.
    // The wider sign-out is a card at the foot of the Overview page and says
    // which of the two reaches further; both are drawn, neither is quiet.
    '<header class="pagehead"><div><h1>' + esc(heading) + '</h1>' +
    '<p class="who">Signed in as <strong>' +
    esc(session.user.username) + '</strong></p></div>' +
    '<form method="post" action="' + BASE + '/signout">' + csrf +
    '<button class="secondary" title="' +
    esc('Ends this portal session and the sign-on session behind it — this ' +
        'browser\'s sessions. It does not revoke tokens or tickets already ' +
        'issued to applications; Sign out of everything, on the Overview ' +
        'page, does.') +
    '">Sign out</button></form></header>' +
    '<div class="shell">' +
    '<div class="side"><div class="card">' + navBar(active) + '</div></div>' +
    '<div class="main">' +
    (error ? '<div class="err">' + esc(error) + '</div>' : '') +
    (message ? '<div class="ok">' + esc(message) + '</div>' : '') +
    cards +
    '</div></div>', true);
  log.debug('Leaving shell(). ' + heading + '.');
  return html;
}

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

function activationForm(base, username, token, message, error) {
  const csrfless = ''; // the form carries the token instead; see below
  return page('Set up your account',
    '<div class="card">' +
    '<h1>Set up your account</h1>' +
    '<p class="sub">You are setting up how <strong>' + esc(username) +
    '</strong> will sign in to <code>' + esc(base) + '</code>.</p>' +
    (error ? '<div class="err">' + esc(error) + '</div>' : '') +
    (message ? '<div class="ok">' + esc(message) + '</div>' : '') +
    '<form method="post" action="' + ACTIVATE + '">' +
    // THE TOKEN RIDES IN THE FORM, and this is the one place in this service a
    // credential is a hidden field. It is unavoidable: the person is not signed
    // in, so there is no session to carry state on, and the alternative — a
    // server-side pending record keyed by something else — would be a second
    // credential protecting the first. It is a POST so the token does not end
    // up in a referer or an access log the way a GET's query string does.
    '<input type="hidden" name="user" value="' + esc(username) + '">' +
    '<input type="hidden" name="token" value="' + esc(token) + '">' +
    '<h2>1. A password</h2>' +
    '<label for="password">Password</label>' +
    '<input type="password" id="password" name="password" autocomplete="new-password">' +
    '<label for="confirm">Confirm it</label>' +
    '<input type="password" id="confirm" name="confirm" autocomplete="new-password">' +
    '<p class="note">Leave both empty if you would rather sign in with a ' +
    'security key alone. You need at least one of the two.</p>' +
    '<h2>2. A security key</h2>' +
    '<p class="note">A security key can be your ONLY credential (you sign in ' +
    'with the key and no password) or a SECOND factor beside a password. ' +
    'This service supports no other second factor.</p>' +
    '<label class="chk"><input type="radio" name="key_role" value="none" checked> ' +
    'No security key for now</label>' +
    '<label class="chk"><input type="radio" name="key_role" value="primary"> ' +
    'Use a security key instead of a password</label>' +
    '<label class="chk"><input type="radio" name="key_role" value="mfa"> ' +
    'Use a security key as a second factor, with the password above</label>' +
    '<p class="note">Choosing a security key takes you to the enrolment screen ' +
    'after this step.</p>' +
    '<button type="submit">Continue</button>' +
    '</form>' +
    '</div>');
}

// ---------------------------------------------------------------------------
// WHAT THE FIVE PORTAL ROUTES TAKE, AND THE ONE THAT IS ALLOWED A USERNAME.
//
// The rule at the top of this file is that no route here takes an identity from
// the request — every page reads `sessionOf(req).user.username`, so there is no
// parameter for anybody to change. **These schemas are the mechanical statement
// of that rule**: four of the five declare no identity field at all, and a
// reader checking whether the rule still holds can read five short objects
// instead of five handlers.
//
// `/portal/activate` is the exception and it is not one: it takes a username
// BECAUSE nobody is signed in, and what authorises it is the token beside it,
// which is a credential.
//
// **`done` IS THE ONE REFLECTED VALUE ON THIS SURFACE.** This service puts it
// in a `Location` after a successful change and reads it straight back onto the
// page — so anybody can craft `/portal?done=<anything>` and have it rendered.
// It is escaped through `esc()` and this console is `script-src 'none'`, so the
// bound here is depth rather than the fix; what it removes is the megabyte
// version and the one with a NUL in it.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// A REFUSAL FROM `common/validation.js`, RENDERED AS A PAGE.
//
// That module returns a code, a field and a sentence and renders nothing; this
// surface answers a person in a browser, so the sentence goes on a page in this
// portal's own shell rather than into a JSON body nobody here would see.
//
// 400 and not 403: nothing was refused about WHO is asking. The request was
// malformed, which is true whether or not anybody is signed in — the same line
// `common/validation.js` draws between shape and existence.
// ---------------------------------------------------------------------------
function refuseShape(res, why) {
  log.debug('Entering refuseShape(). code=' + why.code + ' field=' + why.field);
  log.debug('Leaving refuseShape().');
  return send(res, 400, page('Bad request',
    '<div class="card"><h1>Bad request</h1><p class="err">' +
    esc(why.detail) + '</p></div>'));
}

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

app.get(ACTIVATE, function (req, res) {
  log.debug('Entering GET ' + ACTIVATE + '.');
  const asked = validation.check(req, 'query', ACTIVATE_QUERY);
  if (!asked.ok) {
    return refuseShape(res, asked);
  }
  const username = String(asked.value.user || '').trim();
  const token = String(asked.value.token || '');
  // RATE LIMITED even on the GET: this endpoint takes a credential, and an
  // endpoint that takes a credential must not be the one place in this service
  // that answers guesses at network speed.
  const allowed = websecurity.attempt('activation', req, username);
  if (!allowed.ok) {
    log.debug('Leaving GET ' + ACTIVATE + '. Rate limited.');
    return send(res, 429, page('Too many attempts',
      '<div class="card"><h1>Too many attempts</h1><p>' +
      esc(allowed.detail) + '</p></div>'));
  }
  const checked = credentials.checkActivation(username, token);
  if (!checked.ok) {
    log.info('portal: an activation link was refused for "' + username +
             '" (' + checked.reason + ').');
    audit.record({
      category: 'authentication', action: 'portal.activate.refused',
      actor: username, outcome: 'failure',
      summary: 'an activation link was refused',
      detail: { reason: checked.reason, address: websecurity.addressOf(req) }
    });
    log.debug('Leaving GET ' + ACTIVATE + '. Refused.');
    return send(res, 400, page('Activation link',
      '<div class="card"><h1>Activation link</h1><div class="err">' +
      esc(ACTIVATION_REFUSAL) + '</div></div>'));
  }
  log.debug('Leaving GET ' + ACTIVATE + '. Drawing the setup form.');
  return send(res, 200, activationForm(baseUrlOf(req), username, token, null, null));
});

app.post(ACTIVATE, function (req, res) {
  log.debug('Entering POST ' + ACTIVATE + '.');
  // `parseBody()` and not `req.body`: this service parses every body as raw
  // text, so `checkParsed()` is the entry point. Its header argues why.
  const posted = validation.checkParsed(parseBody(req), 'body', ACTIVATE_FORM);
  if (!posted.ok) {
    return refuseShape(res, posted);
  }
  const body = posted.value;
  const username = String(body.user || '').trim();
  const token = String(body.token || '');
  const base = baseUrlOf(req);

  const allowed = websecurity.attempt('activation', req, username);
  if (!allowed.ok) {
    log.debug('Leaving POST ' + ACTIVATE + '. Rate limited.');
    return send(res, 429, page('Too many attempts',
      '<div class="card"><h1>Too many attempts</h1><p>' +
      esc(allowed.detail) + '</p></div>'));
  }
  // **THE TOKEN IS CHECKED AGAIN ON THE POST**, and not merely on the GET that
  // drew the form. A form is markup; the door is here. A POST assembled by hand
  // never met the GET at all.
  const checked = credentials.checkActivation(username, token);
  if (!checked.ok) {
    log.info('portal: an activation POST was refused for "' + username +
             '" (' + checked.reason + ').');
    log.debug('Leaving POST ' + ACTIVATE + '. Refused.');
    return send(res, 400, page('Activation link',
      '<div class="card"><h1>Activation link</h1><div class="err">' +
      esc(ACTIVATION_REFUSAL) + '</div></div>'));
  }

  const password = String(body.password || '');
  const confirm = String(body.confirm || '');
  const keyRole = String(body.key_role || 'none');

  if (password && password !== confirm) {
    return send(res, 400, activationForm(base, username, token, null,
      'The two passwords do not match.'));
  }
  // **AT LEAST ONE WAY IN, AND THE COMBINATION THAT IS NOT ONE IS REFUSED
  // HERE.** A security key marked `mfa` is a SECOND factor — it is not a way to
  // sign in by itself — so choosing it with no password would finish the setup
  // with an account nobody can use, including its owner. That is the same
  // lockout `credentials.removeKey()` refuses to create, caught at the other
  // end of the same rule.
  if (!password && keyRole !== 'primary') {
    return send(res, 400, activationForm(base, username, token, null,
      keyRole === 'mfa'
        ? 'A security key used as a SECOND factor needs a password to be the ' +
          'first one. Set a password as well, or choose to use the key instead ' +
          'of a password.'
        : 'Set a password, or choose to use a security key instead of one. ' +
          'You need at least one way to sign in.'));
  }
  if (password) {
    const set = credentials.setPassword(username, password);
    if (!set.ok) {
      return send(res, 400, activationForm(base, username, token, null,
        (set.errors || ['The password could not be set.'])[0]));
    }
  }

  // **THE LINK IS SPENT HERE**, once the account really can be used. Spending
  // it earlier would strand somebody whose password was refused.
  credentials.consumeActivation(username);
  audit.record({
    category: 'authentication', action: 'portal.activate',
    actor: username, outcome: 'success',
    summary: username + ' completed account setup',
    detail: { password: !!password, keyRole: keyRole,
              address: websecurity.addressOf(req) }
  });
  log.info('portal: ' + username + ' completed account setup (' +
           (password ? 'password' : 'no password') + ', security key: ' +
           keyRole + '). The activation link is now spent.');

  // **THEY ARE SENT TO THE SIGN-IN SCREEN AND NOT SIGNED IN.** Spending an
  // activation link proves possession of a link, which is not the credential
  // they have just configured — and a link that both set up an account and
  // granted a session would be a standing bypass of every mechanism the person
  // chose. So the last step of setup is to use it.
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
  // `/portal` has no session, `requireSignIn()` calls `beginAuthentication()`,
  // and the screen is reached with a record behind it. Two properties are
  // worth keeping if this is ever reworked:
  //
  //   * **The record is minted when the link is PRESSED, not when this page is
  //     drawn.** Calling `beginAuthentication()` here and pasting the returned
  //     URL into the anchor would work and would then expire: a pending record
  //     has a lifetime, and somebody who sets a password and reads the page
  //     before clicking would meet the very error this replaces.
  //   * **They land on their own account page**, which is the right
  //     destination for somebody who has just set an account up — and the only
  //     destination this service can name, since an activation link belongs to
  //     no application and there is no flow in progress to resume.
  //
  // Both branches are therefore the same address, and the difference between
  // them is PROSE rather than a destination: with a key still to enrol they
  // are told why signing in comes first (enrolling one requires knowing who is
  // asking, and until they sign in nobody does).
  const next = BASE;
  log.debug('Leaving POST ' + ACTIVATE + '. Set up; sending to sign in.');
  return send(res, 200, page('Account ready',
    '<div class="card"><h1>Your account is ready</h1>' +
    '<div class="ok">' +
    esc(password ? 'Your password is set.' : 'Your account is set up.') +
    ' This activation link has now been used and will not work again.</div>' +
    (keyRole !== 'none'
      ? '<p>You asked to use a security key' +
        (keyRole === 'mfa' ? ' as a second factor' : ' instead of a password') +
        '. A key is enrolled DURING A SIGN-IN rather than from your account ' +
        'pages: tick the security-key box at the sign-in screen and the first ' +
        'use enrols it. There is no enrol button on your Security keys page, ' +
        'because a WebAuthn ceremony belongs to a sign-in — which is the ' +
        'same reason nothing here links to /authn/webauthn.</p>'
      : '') +
    '<p><a href="' + esc(next) + '">Sign in</a></p></div>'));
});

// ---------------------------------------------------------------------------
// THE AUTHENTICATED PORTAL.
//
// **THE IDENTITY COMES FROM THE SESSION AND NOWHERE ELSE.** Not from a query
// parameter, not from a body field, not from a header. There is nothing here
// for anybody to change, which is the only version of OWASP A01 that survives
// somebody adding a page later without reading this comment.
// ---------------------------------------------------------------------------
function requireSignIn(req, res, returnTo, want) {
  // THE PORTAL'S OWN SESSION AND NOT THE SIGN-ON SESSION (2026-09-06). This is
  // a relying party: it reads the session it established from an ID Token, in
  // its own cookie. `authn.sessionOf()` would be this portal reading the
  // identity provider's cookie, which is the arrangement the code flow
  // replaced — and it would also mean a person who signed in to any other
  // family here was silently already signed in to their account page, which is
  // single sign-on happening without an application ever having asked for it.
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
    // `session.user.username` — and the policy's owner arm is what permits it.
    // That looks circular and is the point: it is written as a comparison
    // between two attributes rather than as an equality buried in a handler,
    // so a deployment that wants a HELPDESK ROLE able to manage somebody
    // else's account adds a rule instead of changing this file. Until then the
    // owner and the subject are the same name and the answer is the same
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
      send(res, 403, page('Not permitted',
        '<div class="card"><h1>Not permitted</h1>' +
        '<div class="err">' + esc(answer.why) + '</div>' +
        '<p class="note">This is a policy decision rather than a missing ' +
        'sign-in. You are signed in as <strong>' +
        esc(session.user.username) + '</strong>.</p></div>'));
      return null;
    }
    return session;
  }
  // ---------------------------------------------------------------------
  // **THROUGH `beginAuthentication()` AND NOT A BARE REDIRECT TO THE LOGIN
  // PATH**, which is what this did at first and what does not work.
  //
  // `/authn/login` is not a page somebody can simply be sent to: it draws a
  // form for a PENDING AUTHENTICATION RECORD, and a POST that names no record
  // is answered `This sign-in form has expired`. Every other flow here enters
  // it the same way — `saml2_sso.js`, `consent_screen.js`, `wsfed.js` — by
  // asking this function for the address to send the browser to, and the
  // portal is no different from them in this respect even though it is not a
  // protocol.
  //
  // `returnTo` is a path on THIS service, which is what that function requires
  // and refuses anything else, so the portal cannot be used as an open
  // redirect by asking it to send somebody somewhere after signing in.
  // ---------------------------------------------------------------------
  // -------------------------------------------------------------------
  // **AND IT IS AN AUTHORIZATION CODE FLOW SINCE 2026-09-06.** Everything the
  // comment above says about not being able to redirect straight to
  // `/authn/login` is still true and is now true one layer down: this portal
  // does not reach for the sign-on session at all. It sends the browser to
  // `/oauth2/authorize` as `sts-user-portal`, and the sign-in screen is reached
  // — if it is reached at all — because the AUTHORIZATION ENDPOINT decided it
  // needed one. A person who already signed in somewhere else in this service
  // comes straight back with a code, which is single sign-on falling out of the
  // protocol rather than out of a shared cookie.
  //
  // **THE `application` SENTENCE ABOVE IS REVERSED AND THE ENTRY IS REAL.** It
  // said the portal is not an application — nobody registered it, it issues no
  // token, and naming one would put a fictional entry in the registry. It IS
  // one now: `sts-user-portal` is seeded under `ou=applications` at startup
  // (`applications.seedInternal`), it is what the role gate is handed, and it
  // is what a person consents to. What made the old sentence right was that
  // there was no such entry; what makes it wrong now is that there is, and it
  // was written by this service rather than invented in a parameter.
  //
  // `returnTo` is still a path on this service, checked by `oidc_rp.js` the way
  // `beginAuthentication()` checked it AND held server-side, so the portal
  // still cannot be turned into an open redirect.
  // -------------------------------------------------------------------
  const started = oidcRp.beginSignIn(req, res, 'portal', {
    returnTo: returnTo || BASE,
    fallback: BASE
  });
  if (!started.ok) {
    // The client entry is gone or has no secret. A refusal with the reason on
    // it rather than a redirect into a flow that cannot complete — and it names
    // the entry, because that is where somebody has to look.
    log.error('portal: nobody can sign in. ' + started.why);
    send(res, 503, page('The portal cannot sign anybody in',
      '<div class="card"><h1>The portal cannot sign anybody in</h1>' +
      '<div class="err">' + esc(started.why) + '</div>' +
      '<p class="note">This portal signs people in through this service\'s own ' +
      'authorization server, as the registered client ' +
      '<code>sts-user-portal</code>. That entry is seeded at startup and lives ' +
      'under <code>ou=applications</code> like any other application, so it can ' +
      'be edited and deleted like any other &mdash; which is what has ' +
      'happened.</p></div>'));
  }
  return null;
}

// ---------------------------------------------------------------------------
// THE OVERVIEW. What this identity provider knows about the person looking at
// it, and the one act that reaches further than the button in the header.
//
// **IT NO LONGER HOLDS THE PASSWORD FORM OR THE KEY LIST**, which moved to
// pages of their own when this application grew a column. What is left here is
// a SUMMARY of both with a link to each — two facts and two links, rather than
// two forms — because "have I got a password, and is a second factor turned
// on" is the first thing somebody wants from an account page and the last
// thing they want to hunt for.
// ---------------------------------------------------------------------------
function overviewPage(session, message, error) {
  log.debug('Entering overviewPage().');
  const username = session.user.username;
  const mechanisms = credentials.mechanismsFor(username);
  const csrf = websecurity.field(session.id);
  const detail = stats.userDetail ? stats.userDetail(username) : null;

  const html = shell(BASE, session, message, error,
    '<div class="card">' +
    '<h2>You</h2>' +
    '<p class="sub">What this identity provider knows about you, and how you ' +
    'signed in to this page.</p>' +
    '<table>' +
    '<tr><th>Username</th><td>' + esc(username) + '</td></tr>' +
    '<tr><th>Subject</th><td><code>' + esc(session.user.sub || '') +
      '</code></td></tr>' +
    (session.user.email
      ? '<tr><th>Email</th><td>' + esc(session.user.email) + '</td></tr>' : '') +
    (session.user.name
      ? '<tr><th>Name</th><td>' + esc(session.user.name) + '</td></tr>' : '') +
    '<tr><th>Signed in</th><td>' +
      esc(new Date((session.authTime || 0) * 1000).toISOString()) + '</td></tr>' +
    '<tr><th>How</th><td>' + esc((session.amr || []).join(', ') || 'unstated') +
      ' (acr ' + esc(session.acr || '') + ')</td></tr>' +
    '<tr><th>This session ends</th><td>' +
      esc(new Date(session.expires || 0).toISOString()) + '</td></tr>' +
    (detail
      ? '<tr><th>Times you have signed in</th><td>' +
        esc(String(detail.authentications || 0)) + '</td></tr>'
      : '') +
    '</table>' +
    '</div>' +

    '<div class="card">' +
    '<h2>How you sign in</h2>' +
    '<table>' +
    '<tr><th>Password</th><td>' +
      (mechanisms.password ? 'set' : '<em>none set</em>') +
      ' — <a href="' + esc(BASE + '/password') + '">change it</a></td></tr>' +
    '<tr><th>Security keys</th><td>' +
      (mechanisms.keys.length
        ? esc(String(mechanisms.keys.length)) + ' enrolled'
        : '<em>none enrolled</em>') +
      ' — <a href="' + esc(BASE + '/keys') + '">see them</a></td></tr>' +
    '<tr><th>Second factor</th><td>' +
      (mechanisms.mfaRequired
        ? 'required — you hold a key marked as a second factor'
        : 'not required') + '</td></tr>' +
    '</table>' +
    '</div>' +

    '<div class="card">' +
    '<h2>Sign out of everything</h2>' +
    '<form method="post" action="/logout">' + csrf +
    '<button class="secondary">Sign out of everything</button></form>' +
    '<p class="note">Ends every session you hold here, in every protocol, and ' +
    'tells the applications that can be told — access and refresh tokens, ' +
    'Kerberos tickets, credential offers, LDAP binds, the lot. <strong>The ' +
    'Sign out button at the top of every page is the narrower one</strong>: it ' +
    'ends this browser\'s sessions and leaves what has already been issued to ' +
    'applications alone. Two different acts, and this is the one that reaches ' +
    'further.</p>' +
    '</div>');
  log.debug('Leaving overviewPage().');
  return html;
}

// ---------------------------------------------------------------------------
// THE PASSWORD PAGE. One form, and the argument for the field somebody signed
// in already has to fill in anyway.
// ---------------------------------------------------------------------------
function passwordPage(session, message, error) {
  log.debug('Entering passwordPage().');
  const mechanisms = credentials.mechanismsFor(session.user.username);
  const csrf = websecurity.field(session.id);

  const html = shell(BASE + '/password', session, message, error,
    '<div class="card">' +
    '<p class="sub">' +
    (mechanisms.password
      ? 'You have a password set.'
      : 'You have NO password set. Setting one here needs the current one, ' +
        'which you do not have — so a password is set through an activation ' +
        'link from whoever administers this service, or at ' +
        '<code>/portal/activate</code>.') +
    '</p>' +
    '<form method="post" action="' + BASE + '/password">' + csrf +
    '<label for="current">Your current password</label>' +
    '<input type="password" id="current" name="current" autocomplete="current-password">' +
    '<label for="next">New password</label>' +
    '<input type="password" id="next" name="next" autocomplete="new-password">' +
    '<label for="confirm">Confirm it</label>' +
    '<input type="password" id="confirm" name="confirm" autocomplete="new-password">' +
    '<button type="submit">Change password</button>' +
    '</form>' +
    '<p class="note">Your current password is required even though you are ' +
    'already signed in: a session somebody left open on a shared machine must ' +
    'not be enough to take the account over.</p>' +
    '</div>');
  log.debug('Leaving passwordPage().');
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
function keysPage(session, message, error) {
  log.debug('Entering keysPage().');
  const mechanisms = credentials.mechanismsFor(session.user.username);
  const csrf = websecurity.field(session.id);
  const keys = mechanisms.keys;

  const html = shell(BASE + '/keys', session, message, error,
    '<div class="card">' +
    '<p class="sub">' + (keys.length
      ? esc(String(keys.length)) + ' enrolled. ' +
        (mechanisms.mfaRequired
          ? 'One of them is marked as a second factor, so a password alone ' +
            'will not sign you in.'
          : 'None of them is marked as a second factor.')
      : 'You have no security keys enrolled.') + '</p>' +
    (keys.length
      ? '<table class="grid"><tr><th>Key</th><th>Role</th><th>Enrolled</th>' +
        '<th></th></tr>' +
        keys.map(function (one) {
          return '<tr><td>' + esc(one.label || 'security key') + '</td>' +
            '<td>' + esc(one.role) + '</td>' +
            '<td>' + esc(new Date(one.enrolledAt || 0).toISOString().slice(0, 10)) +
            '</td><td>' +
            '<form method="post" action="' + BASE + '/remove-key">' + csrf +
            '<input type="hidden" name="credentialId" value="' +
            esc(one.credentialId) + '">' +
            '<button class="danger">Remove</button></form></td></tr>';
        }).join('') + '</table>'
      : '') +
    '<p class="note">A security key is either your ONLY credential (you sign ' +
    'in with the key and no password) or a SECOND factor beside a password. ' +
    'This service supports no other second factor. You cannot remove your last ' +
    'way in — set another one first.</p>' +
    // NO LINK TO `/authn/webauthn`, AND THAT IS THE RULE THIS DIRECTORY
    // LEARNED THE HARD WAY. That page is a STEP IN A SIGN-IN — it draws the
    // ceremony for a PENDING AUTHENTICATION RECORD — so a link to it from here
    // is the same defect as the account-ready page's link to `/authn/login`
    // was: a control that looks like a way to enrol a key and answers that the
    // sign-in form has expired. `/authn/login is never a destination` reads off
    // every page that starts a sign-in, and this is one of them.
    '<p class="note">A key is enrolled DURING A SIGN-IN — tick the ' +
    'security-key box at the sign-in screen, and the first use enrols — or ' +
    'when an activation link is spent. There is no enrol button here, ' +
    'because a WebAuthn ceremony belongs to a sign-in and this page is not ' +
    'one.</p>' +
    '</div>');
  log.debug('Leaving keysPage().');
  return html;
}

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
// is ungated by design and hands the whole registry to anybody who can reach
// the port; `admin-ui/CLAUDE.md` and `mgmt-api/CLAUDE.md` both argue that at
// length. This is a page choosing not to answer a question it was not asked,
// which is a different thing from a page that could not answer it.
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
// The flag is honoured in `xacml/xacml_role_pep.js`, which is where the audit
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

// How many entries the page will evaluate. A GUARD AND NOT A SETTING: a
// deployment with a registry this size has an operator's problem rather than a
// person's, and a configuration row would be a knob nobody turns until the day
// the page has already been slow. Each entry costs one policy evaluation per
// distinct issuance kind it has, on the one thread that answers every socket
// this service holds — which is the stall `CLAUDE.md`'s worker-pool section is
// about, so the cap is here rather than left to be discovered. The page says
// when it bites.
const SCAN_LIMIT = 1000;

// Rows per page. The registry is paginated for the same reason /admin's is:
// a list that draws every row is a list that stops working at some size and
// gives no sign of approaching it.
const PER_PAGE = 20;

// Which of the five this entry is a sign-in destination in. DECLARED and
// OBSERVED both count, and the union is deliberate: an entry an operator
// created and ticked SAML 2.0 on has never been seen, and one that has been
// signing people in for a month may never have been declared anything. Either
// is an answer to "could I sign in to this".
function signInFamiliesOf(row) {
  const declared = row.allowedProtocols || [];
  const recorded = row.recordedProtocols || [];
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
// request — a policy that says something different about an ID Token from what
// it says about a SAML assertion is a policy somebody may write, and a page
// that asked about one and reported the other would be wrong in exactly the
// case the person cared about.
//
// An application is listed if ANY of its kinds is permitted, and the row says
// which — "permitted for a SAML 2.0 assertion, refused for an access token" is
// the true answer and is drawn as such.
// ---------------------------------------------------------------------------
function applicationsFor(username) {
  log.debug('Entering applicationsFor(). username=' + username);
  const all = applications.list();
  const scanned = all.slice(0, SCAN_LIMIT);
  const rows = [];
  let refused = 0;
  let notSignIn = 0;

  scanned.forEach(function (one) {
    const families = signInFamiliesOf(one);
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
      // The first description on the entry, if it carries one. An application
      // registered by a client has none; one an operator created usually does.
      description: (one.descriptions || [])[0] || '',
      families: permitted.map(function (family) {
        const detail = applications.protocolRow(family.protocol);
        return detail ? detail.label : family.protocol;
      }),
      ways: permitted.map(function (family) { return family.how; })
        .filter(function (how, at, list) { return list.indexOf(how) === at; }),
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
  // sorts by when each was last seen, which is the right order for an operator
  // watching traffic and the wrong one for a person looking for an application
  // by name: it reshuffles between page loads for reasons that have nothing to
  // do with the reader.
  rows.sort(function (a, b) {
    return a.name.toLowerCase().localeCompare(b.name.toLowerCase()) ||
           a.identifier.localeCompare(b.identifier);
  });

  log.debug('Leaving applicationsFor(). ' + rows.length + ' permitted, ' +
            refused + ' refused, ' + notSignIn + ' not sign-in destinations.');
  return { rows: rows, refused: refused, notSignIn: notSignIn,
           scanned: scanned.length, total: all.length,
           truncated: all.length > scanned.length };
}

function applicationsPage(session, message, error, wanted) {
  log.debug('Entering applicationsPage().');
  const found = applicationsFor(session.user.username);
  const pages = Math.max(1, Math.ceil(found.rows.length / PER_PAGE));
  const at = Math.min(Math.max(1, wanted || 1), pages);
  const shown = found.rows.slice((at - 1) * PER_PAGE, at * PER_PAGE);

  const table = shown.length
    ? '<table class="grid"><tr><th>Application</th><th>Sign-in</th>' +
      '<th>You would be issued</th></tr>' +
      shown.map(function (row) {
        return '<tr><td><strong>' + esc(row.name) + '</strong>' +
          '<span class="ident"><code>' + esc(row.identifier) + '</code></span>' +
          (row.description
            ? '<span class="ident">' + esc(row.description) + '</span>' : '') +
          '</td><td>' +
          row.families.map(function (label) {
            return '<span class="tag">' + esc(label) + '</span>';
          }).join('') +
          (row.withheld.length
            ? '<span class="ident">not ' + esc(row.withheld.join(', ')) +
              ' — the policy permits the other' +
              (row.families.length === 1 ? '' : 's') + '</span>'
            : '') +
          '</td><td>' + esc(row.ways.join(', ')) + '</td></tr>';
      }).join('') + '</table>'
    : '<p class="note">There is nothing here yet. Either this service has no ' +
      'applications registered that sign people in, or the issuance policy ' +
      'does not permit you any of them.</p>';

  const paging = pages > 1
    ? '<p class="pagenav">' +
      (at > 1
        ? '<a href="' + esc(BASE + '/applications?page=' + (at - 1)) +
          '">Previous</a>'
        : '<span class="off">Previous</span>') +
      '<span class="here">Page ' + esc(String(at)) + ' of ' +
      esc(String(pages)) + '</span>' +
      (at < pages
        ? '<a href="' + esc(BASE + '/applications?page=' + (at + 1)) +
          '">Next</a>'
        : '<span class="off">Next</span>') +
      '</p>'
    : '';

  const html = shell(BASE + '/applications', session, message, error,
    '<div class="card">' +
    '<p class="sub">Where this identity provider will sign you in. Each row ' +
    'was decided by the SAME policy the token endpoint, both SAML profiles ' +
    'and WS-Federation ask before they issue anything — so this page and those ' +
    'endpoints cannot disagree.</p>' +
    table + paging +
    '</div>' +

    '<div class="card">' +
    '<h2>What is not on this list</h2>' +
    '<table>' +
    '<tr><th>Not permitted to you</th><td>' +
      esc(String(found.refused)) +
      (found.refused === 1 ? ' application' : ' applications') +
      '. They are counted rather than named: which applications exist here is ' +
      'not a question this page answers. Whoever administers this service ' +
      'decides, by giving your account a role the application requires.' +
      '</td></tr>' +
    '<tr><th>Not sign-in destinations</th><td>' +
      esc(String(found.notSignIn)) +
      (found.notSignIn === 1 ? ' entry' : ' entries') +
      '. A registered application is not necessarily somewhere a person signs ' +
      'in — a Shared Signals receiver, a SCIM provisioning client, an LDAP ' +
      'binder, a SPIFFE workload or a WS-Trust relying party is an ' +
      'application this service knows and not a door you walk through.' +
      '</td></tr>' +
    (found.truncated
      ? '<tr><th>Not looked at</th><td>' +
        esc(String(found.total - found.scanned)) + ' of ' +
        esc(String(found.total)) + ' entries. This page evaluates the ' +
        'issuance policy for each application it lists and stops at ' +
        esc(String(SCAN_LIMIT)) + ', because that work happens on the one ' +
        'thread answering every socket this service holds.</td></tr>'
      : '') +
    '</table>' +
    '<p class="note">There is no button to launch any of these, and that is ' +
    'deliberate rather than missing: this service implements no ' +
    'identity-provider-initiated sign-on in any of the four browser profiles ' +
    '— <code>/saml2</code> says so on its own page — so a link from here ' +
    'would have to invent a request the application never asked for and is ' +
    'not expecting. A sign-in starts at the application.</p>' +
    '</div>');
  log.debug('Leaving applicationsPage(). Page ' + at + ' of ' + pages + '.');
  return html;
}

// ===========================================================================
// THE REDIRECT URI. WHERE THE AUTHORIZATION ENDPOINT SENDS THE BROWSER BACK.
//
// Registered ABOVE the portal's own pages so that a reader meets it beside
// `requireSignIn()`, which is the function that sends people away in the first
// place. There is no gate over `/portal` — every page here calls
// `requireSignIn()` itself — so unlike the console's callback this one needs no
// exemption from anything; it simply does not call that function.
//
// Everything it does is in `common/oidc_rp.js`. What is here is where to go
// afterwards and what a refusal looks like in the portal's own shell, which is
// a different application from the console's and draws its own.
// ===========================================================================
app.get(BASE + '/callback', function (req, res) {
  log.debug('Entering ' + BASE + '/callback.');
  oidcRp.handleCallback(req, res, 'portal').then(function (answer) {
    if (!answer.ok) {
      log.info('portal: a sign-in did not complete. ' + answer.why);
      send(res, 400, page('Signing in did not complete',
        '<div class="card"><h1>Signing in did not complete</h1>' +
        '<div class="err">' + esc(answer.why) + '</div>' +
        '<p>This portal signs you in through this service\'s own sign-in ' +
        'service, using the ordinary OpenID Connect authorization code flow — ' +
        'the same one any other application here would use. What failed above ' +
        'is one step of that flow, named exactly rather than reported as ' +
        '&ldquo;sign-in failed&rdquo;.</p>' +
        '<p><a href="' + esc(BASE) + '">Try again</a></p></div>'));
      log.debug('Leaving ' + BASE + '/callback. Refused.');
      return;
    }
    res.status(303).set('Cache-Control', 'no-store')
       .set('Location', answer.returnTo || BASE).end();
    log.debug('Leaving ' + BASE + '/callback. Signed in as ' + answer.username + '.');
  }).catch(function (e) {
    // A rejection is a bug here rather than anything a request can cause:
    // handleCallback() resolves its refusals. Reported as one.
    log.error('The portal OIDC callback threw: ' + (e.stack || e.message));
    send(res, 500, page('Signing in did not complete',
      '<div class="card"><h1>Signing in did not complete</h1>' +
      '<div class="err">' + esc(e.message) + '</div></div>'));
  });
});

// ---------------------------------------------------------------------------
// THE FOUR SIGNED-IN PAGES. Each one is the same four steps in the same order,
// and the order is the point: SIGN IN (which is also the access decision),
// then VALIDATE what was asked for, then draw.
//
// **THE `returnTo` IS THE PAGE ITSELF ON EVERY ONE OF THEM.** Somebody who
// follows a link to their security keys with no session runs the code flow and
// comes back to their security keys, rather than to the overview with the page
// they asked for forgotten. `oidc_rp.js` holds it server-side and refuses
// anything that is not a path on this service, so four `returnTo`s are no more
// of an open-redirect surface than one was.
//
// **AND THE ACTION IS `READ`, NOT `MANAGE_OWN`.** Drawing a page is reading;
// the three POSTs below ask for `manage-own`. That distinction is the whole
// reason the portal has an action of its own — see `requireSignIn()`, where
// the policy question is argued — and a deployment that later gives a helpdesk
// role the right to READ somebody's account without changing it needs the two
// to have been kept apart from the beginning.
// ---------------------------------------------------------------------------
app.get(BASE, function (req, res) {
  log.debug('Entering GET ' + BASE + '.');
  const session = requireSignIn(req, res, BASE, accessGate.ACTION.READ);
  if (!session) {
    log.debug('Leaving GET ' + BASE + '. Not signed in, or not permitted.');
    return undefined;
  }
  const asked = validation.check(req, 'query', PORTAL_QUERY);
  if (!asked.ok) {
    return refuseShape(res, asked);
  }
  log.debug('Leaving GET ' + BASE + '. Drawn for ' + session.user.username + '.');
  return send(res, 200, overviewPage(session,
    asked.value.done ? String(asked.value.done) : null, null));
});

app.get(BASE + '/applications', function (req, res) {
  log.debug('Entering GET ' + BASE + '/applications.');
  const session = requireSignIn(req, res, BASE + '/applications',
                                accessGate.ACTION.READ);
  if (!session) {
    log.debug('Leaving GET ' + BASE + '/applications. Not signed in, or not ' +
              'permitted.');
    return undefined;
  }
  const asked = validation.check(req, 'query', APPLICATIONS_QUERY);
  if (!asked.ok) {
    return refuseShape(res, asked);
  }
  log.debug('Leaving GET ' + BASE + '/applications. Drawn for ' +
            session.user.username + '.');
  return send(res, 200, applicationsPage(session,
    asked.value.done ? String(asked.value.done) : null, null,
    asked.value.page || 1));
});

// THE PAGE BEHIND THE POST BELOW. Same path, different method: the form has to
// live somewhere now that it is not on the overview, and giving it a path of
// its own would leave the form and the handler that answers it on two
// addresses for no reason anybody could state.
app.get(BASE + '/password', function (req, res) {
  log.debug('Entering GET ' + BASE + '/password.');
  const session = requireSignIn(req, res, BASE + '/password',
                                accessGate.ACTION.READ);
  if (!session) {
    log.debug('Leaving GET ' + BASE + '/password. Not signed in, or not ' +
              'permitted.');
    return undefined;
  }
  const asked = validation.check(req, 'query', PORTAL_QUERY);
  if (!asked.ok) {
    return refuseShape(res, asked);
  }
  log.debug('Leaving GET ' + BASE + '/password. Drawn for ' +
            session.user.username + '.');
  return send(res, 200, passwordPage(session,
    asked.value.done ? String(asked.value.done) : null, null));
});

app.get(BASE + '/keys', function (req, res) {
  log.debug('Entering GET ' + BASE + '/keys.');
  const session = requireSignIn(req, res, BASE + '/keys',
                                accessGate.ACTION.READ);
  if (!session) {
    log.debug('Leaving GET ' + BASE + '/keys. Not signed in, or not permitted.');
    return undefined;
  }
  const asked = validation.check(req, 'query', PORTAL_QUERY);
  if (!asked.ok) {
    return refuseShape(res, asked);
  }
  log.debug('Leaving GET ' + BASE + '/keys. Drawn for ' +
            session.user.username + '.');
  return send(res, 200, keysPage(session,
    asked.value.done ? String(asked.value.done) : null, null));
});

// ---------------------------------------------------------------------------
// CHANGING A PASSWORD. Four controls in one handler, and each is a different
// item on the list.
//
//   CSRF          the token this session's forms carry            (A01/A08)
//   RATE LIMIT    so the current-password check is not an oracle  (A04/A07)
//   RE-AUTH       the current password, even though signed in     (A07)
//   SESSION       the identity from the session, never the body   (A01)
// ---------------------------------------------------------------------------
app.post(BASE + '/password', function (req, res) {
  log.debug('Entering POST ' + BASE + '/password.');
  const session = requireSignIn(req, res, BASE, accessGate.ACTION.MANAGE_OWN);
  if (!session) return undefined;
  const username = session.user.username;
  const posted = validation.checkParsed(parseBody(req), 'body', PASSWORD_FORM);
  if (!posted.ok) {
    return refuseShape(res, posted);
  }
  const body = posted.value;

  const csrf = websecurity.checkCsrf(session.id, body);
  if (!csrf.ok) {
    log.warn('portal: a password change for ' + username + ' was refused on ' +
             'CSRF (' + csrf.reason + ').');
    audit.record({
      category: 'authentication', action: 'portal.password.csrf',
      actor: username, outcome: 'failure',
      summary: 'a password change was refused: ' + csrf.reason,
      detail: { address: websecurity.addressOf(req) }
    });
    log.debug('Leaving POST ' + BASE + '/password. CSRF.');
    return send(res, 403, passwordPage(session, null, csrf.detail));
  }

  const allowed = websecurity.attempt('password-change', req, username);
  if (!allowed.ok) {
    log.debug('Leaving POST ' + BASE + '/password. Rate limited.');
    return send(res, 429, passwordPage(session, null, allowed.detail));
  }

  const current = String(body.current || '');
  const next = String(body.next || '');
  const confirm = String(body.confirm || '');

  // **RE-AUTHENTICATION.** A live session is not enough to change the
  // credential that session was created with — otherwise a browser left open
  // on a shared machine is an account takeover with no credential needed.
  //
  // In DEVELOPMENT mode `verify()` accepts anything, so this is a formality
  // there — which is correct: development checks no password anywhere, and a
  // portal that was the one exception would be a surprise rather than a
  // control.
  const checked = credentials.verify(username, current,
                                     { via: 'the portal password change' });
  if (!checked.ok) {
    log.info('portal: a password change for ' + username + ' was refused (' +
             checked.reason + ').');
    audit.record({
      category: 'authentication', action: 'portal.password.refused',
      actor: username, outcome: 'failure',
      summary: 'a password change was refused',
      detail: { reason: checked.reason, address: websecurity.addressOf(req) }
    });
    log.debug('Leaving POST ' + BASE + '/password. Wrong current password.');
    return send(res, 400, passwordPage(session, null,
      'Your current password is not right.'));
  }
  if (!next || next !== confirm) {
    return send(res, 400, passwordPage(session, null,
      next ? 'The two new passwords do not match.' : 'Give a new password.'));
  }
  const set = credentials.setPassword(username, next);
  if (!set.ok) {
    return send(res, 400, passwordPage(session, null,
      (set.errors || ['The password could not be changed.'])[0]));
  }
  websecurity.succeeded('password-change', req, username);
  audit.record({
    category: 'authentication', action: 'portal.password.changed',
    actor: username, outcome: 'success',
    summary: username + ' changed their own password',
    detail: { address: websecurity.addressOf(req) }
  });
  log.info('portal: ' + username + ' changed their own password.');
  log.debug('Leaving POST ' + BASE + '/password. Changed.');
  // BACK TO THE PAGE IT WAS POSTED FROM, and not to the overview. It used to
  // be the overview because the form was on it; now that the form has a page,
  // a redirect anywhere else would answer "did that work?" by moving the
  // reader somewhere the answer is not.
  res.status(303).set('Location', BASE + '/password?done=' +
    encodeURIComponent('Your password is changed.')).end();
  return undefined;
});

app.post(BASE + '/remove-key', function (req, res) {
  log.debug('Entering POST ' + BASE + '/remove-key.');
  const session = requireSignIn(req, res, BASE, accessGate.ACTION.MANAGE_OWN);
  if (!session) return undefined;
  const username = session.user.username;
  const posted = validation.checkParsed(parseBody(req), 'body', REMOVE_KEY_FORM);
  if (!posted.ok) {
    return refuseShape(res, posted);
  }
  const body = posted.value;

  const csrf = websecurity.checkCsrf(session.id, body);
  if (!csrf.ok) {
    log.debug('Leaving POST ' + BASE + '/remove-key. CSRF.');
    return send(res, 403, keysPage(session, null, csrf.detail));
  }
  // THE CREDENTIAL ID COMES FROM THE BODY AND THE USERNAME DOES NOT, which is
  // the distinction that keeps this safe: `removeKey()` looks the id up among
  // THIS PERSON'S keys, so an id belonging to somebody else matches nothing.
  // An implementation that took both from the request would be the A01
  // vulnerability this file exists to avoid.
  const removed = credentials.removeKey(username,
                                        String(body.credentialId || ''));
  if (!removed.ok) {
    log.debug('Leaving POST ' + BASE + '/remove-key. Refused.');
    return send(res, 400, keysPage(session, null,
      (removed.errors || ['The key could not be removed.'])[0]));
  }
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

// ===========================================================================
// SIGNING OUT (2026-09-06). The other end of the callback above.
//
// **IT ENDS TWO SESSIONS**, for the reason the admin console's own sign-out
// gives at length and which is the same here: this portal is a relying party
// with a session of its own, derived from the SIGN-ON session the person holds
// with this service. Ending only the portal's would be a Sign out button that
// does not sign anybody out — the next request to /portal runs the code flow,
// meets the sign-on session that is still live, and comes straight back in with
// nothing to type.
//
// **IT IS NOT `/logout`, AND THE PAGE AT THE FOOT OF THE ACCOUNT PAGE STILL
// IS.** That endpoint ends everything this identity holds in every protocol —
// tokens, tickets, offers, binds — and it stays exactly where it was, under a
// heading that now says which of the two reaches further. This one is what a
// Sign out button in the corner of a page means everywhere else: this browser
// is done.
//
// **NO `requireSignIn()`**, and that is deliberate rather than an omission. That
// function REDIRECTS a person with no session into the authorization code flow,
// which for a sign-out would send somebody who is already signed out off to
// sign in — the exact opposite of what they pressed. A sign-out asked of a
// browser with no session is not an error either; it is a page saying they are
// signed out, which is true.
// ===========================================================================
app.post(BASE + '/signout', function (req, res) {
  log.debug('Entering POST ' + BASE + '/signout.');
  const session = oidcRp.sessionFor(req, 'portal');
  if (!session) {
    // Nothing to end and nothing to check: there is no session to bind a CSRF
    // token to, and refusing here would only ever refuse somebody who is
    // already in the state they were asking for.
    log.debug('Leaving POST ' + BASE + '/signout. There was no session.');
    return send(res, 200, page('Signed out',
      '<div class="card"><h1>You are signed out</h1>' +
      '<p class="note">There was no portal session on this browser to end.</p>' +
      '<p><a href="' + esc(BASE) + '">Sign in</a></p></div>'));
  }
  const username = session.user.username;
  const body = parseBody(req);
  const csrf = websecurity.checkCsrf(session.id, body);
  if (!csrf.ok) {
    // REFUSED AND NOT PERFORMED, which is worth the line: a sign-out fired from
    // another site is the classic "harmless" CSRF that is not — somebody's
    // session ended under them, repeatedly, with no way to stay signed in.
    log.warn('portal: a sign-out for ' + username + ' was refused on CSRF (' +
             csrf.reason + ').');
    audit.record({
      category: 'authentication', action: 'portal.signout.csrf',
      actor: username, outcome: 'failure',
      summary: 'a sign-out was refused: ' + csrf.reason,
      detail: { address: websecurity.addressOf(req) }
    });
    log.debug('Leaving POST ' + BASE + '/signout. CSRF.');
    return send(res, 403, overviewPage(session, null, csrf.detail));
  }
  const parent = String(session.derivedFrom || '');
  oidcRp.endSessionFor(req, res, 'portal', 'the Sign out button on the user portal');
  const signOnEnded = parent
    ? !!authn.endSessionById(parent, 'the Sign out button on the user portal')
    : false;
  // AND THE SIGN-ON COOKIE. `endSessionById()` takes no response — it is how
  // /logout ends sessions that are not the caller's — so the cookie naming it
  // has to be cleared here, or the browser goes on presenting a session this
  // service no longer holds.
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
  log.info('portal: ' + username + ' signed out. The portal session is gone' +
           (signOnEnded ? ' and so is the sign-on session behind it (' + parent +
                          '), with every session derived from it.'
                        : '; there was no sign-on session left to end.'));
  log.debug('Leaving POST ' + BASE + '/signout. Signed out.');
  return send(res, 200, page('Signed out',
    '<div class="card"><h1>You are signed out</h1>' +
    '<div class="ok">Your portal session has ended' +
    (signOnEnded
      ? ', and so has the sign-on session it was built on — so anything else ' +
        'you were signed in to through it is signed out too.'
      : '. There was no sign-on session left behind it to end.') + '</div>' +
    '<p class="note">Signing out of the portal alone would not have signed you ' +
    'out: this portal is an ordinary OpenID Connect client of this service ' +
    '(<code>sts-user-portal</code>), so the next page would have run the ' +
    'sign-in flow again, met the sign-on session and let you back in with ' +
    'nothing to type.</p>' +
    '<p class="note">Tokens, tickets and other credentials already issued to ' +
    'applications are untouched. <a href="/logout">/logout</a> lists all of ' +
    'them and ends what you choose.</p>' +
    '<p><a href="' + esc(BASE) + '">Sign in again</a></p></div>'));
});

log.info('The User Portal is at ' + BASE + ': a person\'s own account, in ' +
         NAV_PAGES.length + ' pages behind a navigation column of its own — ' +
         'what this identity provider knows about them, WHICH APPLICATIONS ' +
         'THEY MAY SIGN IN TO (decided by the same issuance policy the ' +
         'protocol endpoints ask), their password and their ' +
         'security keys. ' + ACTIVATE + ' is the unauthenticated half, where ' +
         'somebody provisioned through /admin-api or SCIM spends a single-use ' +
         'activation link to set up a credential. Every form carries a CSRF ' +
         'token, every credential endpoint is rate limited, and no route here ' +
         'takes an identity from the request.');

module.exports = {
  BASE: BASE,
  ACTIVATE: ACTIVATE,
  // For sts_metadata.js and the tests.
  // EVERY PATH THIS MODULE REGISTERS, and the signed-in half of it is read off
  // NAV rather than listed again — a page added to the column is a page in this
  // list, and one removed leaves nothing behind for `sts_metadata.js` to report
  // as described-but-not-registered.
  paths: function () {
    return NAV_PAGES.map(function (one) { return one.path; })
      .concat([ACTIVATE, BASE + '/callback', BASE + '/remove-key',
               BASE + '/signout']);
  }
};
