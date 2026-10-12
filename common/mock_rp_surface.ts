// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: mock_rp_surface.ts
//
// ---------------------------------------------------------------------------
// THE MOCK RELYING PARTIES' STATIC SURFACE, ON THE SERVER (#581,
// 2026-10-12).
//
// WS-Federation's `/wsfed/rp`, SAML 2.0's `/saml2/sp` and SAML 1.1's
// `/saml11/rp` are development-only demonstrations (#585) that a person
// starts a sign-in from and reads a verdict on. rcbj decided on #581 to
// convert them rather than delete them, and `common/CLAUDE.md` 3cm holds the
// inventory this module was built from: which of their routes are a page a
// person reads, and which are a protocol peer's door.
//
// ONE SURFACE FOR THE THREE, and the reason is that they are one page in
// three dialects: a start page of sign-in requests to follow, and a verdict
// — the checks a relying party makes, the claims or attributes that
// arrived, the document as it arrived. One bundle (`common/web_mock_rp*.ts`,
// `common/mock-rp-spa.js`) draws all three, over one catalog (`mockRp`) and
// the card (`/web/card.css`, `WebCardCss.MOCK_RP_CSS`).
//
// BUT EACH IS SERVED UNDER ITS OWN FAMILY'S PATH, and that is #472's rule:
// a mock relying party belongs to its family's hosted application, and a
// listener-mapped application loads its script and its API from its own
// listener. So the script is `<base>/mock-rp.js` and the start view
// `<base>/api/start`, for each of the three bases, and nothing new is added
// to `common/hosted_applications.js`'s catalogue.
//
// WHAT THIS MODULE IS NOT: a receiver. Each family's module keeps its own
// assertion consumer — the same fields read, the same verification (#569's
// rule) — and hands this module what it decided.
//
// WHAT IT IS SINCE #590: EACH MOCK RELYING PARTY'S OWN SESSION, which is
// what makes it behave as a real relying party does (rcbj on #590: "I want
// the test to effectively replicate a real world scenario it is trying to
// test"). A real relying party consumes a response at its assertion
// consumer, opens a session of its OWN, and sends the browser on to its
// application with a 303 (POST, redirect, GET); the application learns who
// is signed in from its own back end, with that session. So:
//
//   * `signIn()` — a response that passed every check: any session the
//     browser held here is ended (a sign-in ROTATES the session, as a real
//     one does against fixation), a new one is opened holding the verdict's
//     facts, and the answer is a 303 to the family's application page.
//   * `refuse()` — a response that did not: no session is opened. The
//     refusal is held ONCE for the page to read (on the live session the
//     browser already has, which it does not end, or on a session holding
//     nothing else), and the answer is the receiving door's own status with
//     its error code, as it always was, and the shell, which asks.
//   * `GET <base>/api/session` — what the application page asks: the
//     session's verdict, or the refusal once, or nothing (and the page asks
//     the start view).
//   * `POST <base>/sign-out`, and `end()` / `endWhere()` for the logout
//     messages a family receives (WS-Federation's cleanup, a SAML 2.0
//     LogoutRequest) — the session ends.
//
// THE COOKIE is HttpOnly, SameSite=Lax, Secure where the request reached a
// TLS listener, path-scoped to the family's page under the realm's prefix
// (so it is per realm in the browser as the store is per realm here), and
// lives as long as the session (`<family>.mock*SessionTtlMin`). Its value is
// a random handle that is never stored: the store is keyed by its SHA-256,
// so a row read out of the store does not sign anybody in.
//
// THE STORE is `realms.map()` — per realm at its declaration, the rule
// every store keeps — persisted and short-lived (`retain: 'age'`, its own
// `expires`), so with request workers or a cluster the GET that follows
// the 303 finds the session the POST opened wherever it lands, as
// `wsfed.rpContexts` finds the wctx its start minted. Each key is a random
// handle written once, so a deleted one is TOMBSTONED and a node holding an
// old copy cannot bring back a session another signed out. Expired rows are
// refused where they are read and ejected by the `caches.eject-expired`
// scheduler job (`/admin/caches`, `mockRp.sessions`), never by a timer.
//
// THE START VIEW IS AN API ANSWER, because it MINTS: each family's start is
// where its relying party's own state is made (a `wctx`, a `RelayState`),
// so drawing it again asks again, as loading the old page did.
//
// Every route here carries `common/app.js`'s `demoOnly` mark, as the pages
// do: a product realm answers each as an unrouted path.
// ---------------------------------------------------------------------------

import helpers = require('./helpers');
import config = require('./config');
import realms = require('./realms');
import stsCrypto = require('./crypto');
import cacheRegistry = require('./cache_registry');
import PageLocale = require('./page_locale');
import ShellDocument = require('./shell_document');
import listenerMap = require('./listener_map');
// The demonstration mark (#585). `common/app.js` is required at 2 of the
// require order, so this is a cache hit that moves nothing.
import sharedApp = require('./app');

const { log } = helpers;

type Json = any;
type Req = import('express').Request;
type Res = import('express').Response;

/**
 * One mock relying party: its base path, the words of its shell, and the
 * setting its session's lifetime is.
 */
interface MockRpFamily {
  // The page's path, and the base of its script and its API.
  base: string;
  // The shell's title and `<noscript>` heading, as text.
  title: string;
  // The setting, in minutes, a session it opens lasts (#590).
  sessionTtlSetting: string;
}

/**
 * The three mock relying parties, by the family id the shell names.
 */
const FAMILIES: Record<string, MockRpFamily> = {
  wsfed: { base: '/wsfed/rp',
           title: 'Mock relying party — WS-Federation',
           sessionTtlSetting: 'wsfed.mockRpSessionTtlMin' },
  saml2: { base: '/saml2/sp',
           title: 'Mock service provider — SAML 2.0',
           sessionTtlSetting: 'saml2.mockSpSessionTtlMin' },
  saml11: { base: '/saml11/rp',
            title: 'Mock relying party — SAML 1.1',
            sessionTtlSetting: 'saml11.mockRpSessionTtlMin' }
};

// The build's file (`build-typescript.sh`'s `bundle_surface`; never
// `mock_rp_surface.js`, the server module this file compiles to) and where
// each family serves it.
const BUNDLE_FILE = 'mock-rp-spa.js';
const SCRIPT_NAME = '/mock-rp.js';
const START_PATH = '/api/start';
// What the application page asks (#590), and the relying party's own
// sign-out.
const SESSION_PATH = '/api/session';
const SIGN_OUT_PATH = '/sign-out';

// The cookie's name, before the family; `__Secure-` in front of it over TLS
// (a `__Host-` name would need `Path=/`, and this cookie is scoped to its
// family's page on purpose).
const COOKIE_NAME = 'sts_mockrp_';

// THE BOUND (`docs/caches.md`, rule 3ap): a development-only demonstration's
// sessions, per realm. A constant rather than a setting, because nothing an
// operator runs depends on how many people are signed in to a mock at once:
// past it the OLDEST session is dropped, which signs one tester out of a
// mock — a cost nobody needs to tune.
const MAX_SESSIONS = 1000;

/**
 * One mock relying party's session, as the store holds it.
 */
interface MockRpSession {
  // `wsfed`, `saml2` or `saml11`: a cookie is per family, and a row of
  // another family's is not this one's session.
  family: string;
  // When it was opened and when it ends, epoch milliseconds.
  created: number;
  expires: number;
  // The verdict of the response that signed the person in, or null for a
  // session that holds only a refusal.
  signedIn: Json;
  // A refusal (or a sign-out's outcome) to show ONCE, or null.
  flash: Json;
  // What a family's logout messages are matched on: the subject as the
  // identity provider named it, its format, and SAML 2.0's SessionIndex.
  subject: string;
  nameIdFormat: string;
  sessionIndex: string;
}

// PER TRUST REALM, AT ITS DECLARATION, and persisted: see the header.
const sessions = realms.map({ persist: 'mockRp.sessions', retain: 'age',
                              tombstone: true,
                              // #333: the session's own `expires`, ms.
                              expiresAt: realms.expiryField('expires', 1) });

/**
 * Whether a held session has passed its end — the one test the reader, the
 * bound and the ejector share.
 *
 * @param value - the row
 * @param now - the instant, epoch ms
 * @returns true when it is no longer a session
 */
function sessionExpired(value: Json, now: number): boolean {
  return !value || !(Number(value.expires) > now);
}

// Described to `/admin/caches` (#74, rule 3ap), in `docs/caches.md`'s other
// protocols. A register more than a cache — a row cannot be rebuilt — whose
// keys are digests of the cookies, never the cookies.
const sessionsCount = cacheRegistry.register({
  name: 'mockRp.sessions',
  title: 'Mock relying party sessions',
  description: 'The sessions the three development-only mock relying ' +
    'parties (/wsfed/rp, /saml2/sp, /saml11/rp) open of their own when a ' +
    'response passes their checks, and the refusals they hold once for ' +
    'their pages to read (#590).',
  owner: 'common/mock_rp_surface.ts',
  scope: 'realm',
  persisted: true,
  hitMeaning: 'an application page found the session its cookie names',
  settings: ['wsfed.mockRpSessionTtlMin', 'saml2.mockSpSessionTtlMin',
             'saml11.mockRpSessionTtlMin'],
  maxEntries: function (): number {
    return MAX_SESSIONS;
  },
  bound: 'Enforced: 1000 sessions per realm, expired ones cleared first ' +
    'and then the oldest dropped, which signs that tester out of the mock.',
  lifetime: function (): string {
    return 'Until the family\'s session lifetime passes, its sign-out, or ' +
      'a logout message it receives.';
  },
  eject: cacheRegistry.realmMapEjector(realms, sessions,
    function (value: unknown, key: unknown, now: number): boolean {
      return sessionExpired(value, now);
    }),
  entries: function (): unknown[] {
    return cacheRegistry.realmMapRows(realms, sessions,
      function (value: Json, key: unknown): object {
        return { key: cacheRegistry.digestKey(key),
                 validUntil: Number(value && value.expires) || null,
                 basis: String((value && value.family) || '') };
      });
  }
});

// The built bundle, once read.
let bundleFile: Json = null;

/**
 * The mock relying parties' shell, script, start view and sessions. A static
 * utility class; its state is the built bundle, read once, and the session
 * store above.
 */
class MockRpSurface {
  /**
   * The three families, by id.
   */
  static readonly FAMILIES = FAMILIES;

  /**
   * The path of a family's script.
   *
   * @param family - `wsfed`, `saml2` or `saml11`
   * @returns the path
   */
  static scriptPath(family: string): string {
    log.debug("Entering MockRpSurface.scriptPath(). " + family);
    log.debug("Leaving MockRpSurface.scriptPath().");
    return FAMILIES[family].base + SCRIPT_NAME;
  }

  /**
   * The path of a family's start view.
   *
   * @param family - `wsfed`, `saml2` or `saml11`
   * @returns the path
   */
  static startPath(family: string): string {
    log.debug("Entering MockRpSurface.startPath(). " + family);
    log.debug("Leaving MockRpSurface.startPath().");
    return FAMILIES[family].base + START_PATH;
  }

  /**
   * The path of a family's session view (#590).
   *
   * @param family - `wsfed`, `saml2` or `saml11`
   * @returns the path
   */
  static sessionPath(family: string): string {
    log.debug("Entering MockRpSurface.sessionPath(). " + family);
    log.debug("Leaving MockRpSurface.sessionPath().");
    return FAMILIES[family].base + SESSION_PATH;
  }

  /**
   * The path of a family's own sign-out (#590).
   *
   * @param family - `wsfed`, `saml2` or `saml11`
   * @returns the path
   */
  static signOutPath(family: string): string {
    log.debug("Entering MockRpSurface.signOutPath(). " + family);
    log.debug("Leaving MockRpSurface.signOutPath().");
    return FAMILIES[family].base + SIGN_OUT_PATH;
  }

  /**
   * The family's application page as the browser addresses it: under the
   * realm's prefix, because a `Location` header is not markup and
   * `common/app.js` rewrites only markup into the realm (`common/CLAUDE.md`,
   * the `Location` header). It is also the cookie's path.
   *
   * @param family - `wsfed`, `saml2` or `saml11`
   * @returns the path
   */
  static appPath(family: string): string {
    log.debug("Entering MockRpSurface.appPath(). " + family);
    log.debug("Leaving MockRpSurface.appPath().");
    return realms.currentPrefix() + FAMILIES[family].base;
  }

  /**
   * The surface's bundle and its precompressed forms, read once. A tree
   * that was never built has none, and the shell then loads a script that
   * says so.
   *
   * @returns `ShellDocument.readFile()`'s `{ raw, br, gzip, built }`
   */
  static bundle(): Json {
    log.debug("Entering MockRpSurface.bundle().");
    if (!bundleFile) {
      bundleFile = ShellDocument.readFile(__dirname, BUNDLE_FILE,
        'document.body.textContent = "This service has no mock relying ' +
        'party script (common/' + BUNDLE_FILE + '): it was not built by ' +
        'build-typescript.sh.";');
    }
    log.debug("Leaving MockRpSurface.bundle().");
    return bundleFile;
  }

  /**
   * The sign-in service's base where this listener does not answer it, for
   * the language chooser (`home/home.ts`'s `authnElsewhere()`).
   *
   * @param req - the request
   * @returns the base, or '' where this listener answers it
   */
  static authnElsewhere(req: Json): string {
    log.debug("Entering MockRpSurface.authnElsewhere().");
    let out = '';
    try {
      out = listenerMap.isTrivial() ||
        listenerMap.admits(listenerMap.listenerOf(req), 'authn')
        ? '' : helpers.baseUrlOf(req, 'authn');
    } catch (e) {
      log.debug("Caught in MockRpSurface.authnElsewhere(): " +
                ((e && e.message) || e));
      // A request no listener map can place (an in-process caller): the
      // chooser posts here, as it does on every trivial map.
      out = '';
    }
    log.debug("Leaving MockRpSurface.authnElsewhere(). " + (out || 'here'));
    return out;
  }

  /**
   * The shell document of a family's page. It carries no verdict (#590):
   * the runtime asks the family's session view, and the start view where
   * the session holds nothing.
   *
   * @param req - the request
   * @param family - `wsfed`, `saml2` or `saml11`
   * @returns the document
   */
  static shell(req: Json, family: string): string {
    log.debug("Entering MockRpSurface.shell(). " + family);
    const one = FAMILIES[family];
    const html = ShellDocument.document({
      title: one.title + ' — IYA STS',
      attributes: ([['data-sts-prefix', realms.currentPrefix()],
                    ['data-sts-authn', MockRpSurface.authnElsewhere(req)],
                    ['data-sts-mock-rp', family]] as
                   Array<[string, string]>)
        .concat(PageLocale.shellAttributes(req, '')),
      stylesheets: ['/web/card.css'],
      script: MockRpSurface.scriptPath(family),
      open: '<div class="card mockrp">',
      close: '</div>',
      noscript: '<h1>' + ShellDocument.esc(one.title) + '</h1><div ' +
        'class="err">This page is a script that runs in your browser, and ' +
        'with scripts blocked there is nothing it can show. Allow scripts ' +
        'for this page to start a sign-in or read what arrived.</div>',
      loading: '<p class="sub">Loading&hellip;</p>'
    });
    log.debug("Leaving MockRpSurface.shell().");
    return html;
  }

  /**
   * Sends a family's shell with the status its caller decided — the
   * receiving door's own status for a refusal, which #590 does not change.
   * The caller marks a refusal's error code first.
   *
   * @param req - the request
   * @param res - the response
   * @param status - the status
   * @param family - `wsfed`, `saml2` or `saml11`
   * @returns nothing
   */
  static sendShell(req: Json, res: Res, status: number,
                   family: string): void {
    log.debug("Entering MockRpSurface.sendShell(). " + status);
    const authnAt = MockRpSurface.authnElsewhere(req);
    // error-code: none — the shell's own send; a verdict's code is marked by its caller first.
    res.status(status)
       .type('text/html')
       .set('Cache-Control', 'no-store')
       .set('Content-Security-Policy', ShellDocument.policy(sharedApp, {
         connect: ShellDocument.originsOf([authnAt]),
         csp: { 'style-src': "'self'" } }))
       .send(MockRpSurface.shell(req, family));
    log.debug("Leaving MockRpSurface.sendShell().");
  }

  // --- the session (#590) ---------------------------------------------------

  /**
   * The cookie's name for a family on this request: `__Secure-` in front
   * where the request reached a TLS listener.
   *
   * @param req - the request
   * @param family - `wsfed`, `saml2` or `saml11`
   * @returns the name
   */
  static cookieName(req: Json, family: string): string {
    log.debug("Entering MockRpSurface.cookieName(). " + family);
    log.debug("Leaving MockRpSurface.cookieName().");
    return (req && req.secure ? '__Secure-' : '') + COOKIE_NAME + family;
  }

  /**
   * How long a session the family opens lasts, in milliseconds.
   *
   * @param family - `wsfed`, `saml2` or `saml11`
   * @returns the lifetime
   */
  static sessionTtlMs(family: string): number {
    log.debug("Entering MockRpSurface.sessionTtlMs(). " + family);
    log.debug("Leaving MockRpSurface.sessionTtlMs().");
    return Number(config.value(FAMILIES[family].sessionTtlSetting)) *
      60 * 1000;
  }

  /**
   * The store's key for a cookie's value: its SHA-256, so the store holds
   * nothing a browser could present.
   *
   * @param handle - the cookie's value
   * @returns the key
   */
  static keyOf(handle: string): string {
    log.debug("Entering MockRpSurface.keyOf().");
    log.debug("Leaving MockRpSurface.keyOf().");
    return 'mockrp:' + stsCrypto.digest('sha256', String(handle), 'hex');
  }

  /**
   * The value of the family's cookie on a request, or ''.
   *
   * @param req - the request
   * @param family - `wsfed`, `saml2` or `saml11`
   * @returns the value
   */
  static cookieOf(req: Json, family: string): string {
    log.debug("Entering MockRpSurface.cookieOf(). " + family);
    const name = MockRpSurface.cookieName(req, family);
    const header = String((req && req.headers && req.headers.cookie) || '');
    let found = '';
    header.split(';').forEach(function (part) {
      const at = part.indexOf('=');
      if (at > 0 && part.slice(0, at).trim() === name) {
        found = part.slice(at + 1).trim();
      }
    });
    log.debug("Leaving MockRpSurface.cookieOf(). " +
              (found ? 'present' : 'absent'));
    return found;
  }

  /**
   * Writes the family's cookie: HttpOnly, SameSite=Lax, path-scoped to its
   * page under the realm's prefix, Secure over TLS; an empty value clears
   * it. APPENDED, so a cookie another part of the stack set on the same
   * answer (the cell affinity's) stays.
   *
   * @param req - the request
   * @param res - the response
   * @param family - `wsfed`, `saml2` or `saml11`
   * @param handle - the value, or '' to clear it
   * @param maxAgeS - its lifetime in seconds
   * @returns nothing
   */
  static writeCookie(req: Json, res: Json, family: string, handle: string,
                     maxAgeS: number): void {
    log.debug("Entering MockRpSurface.writeCookie(). " + family + " " +
              (handle ? 'set' : 'clear'));
    const line = MockRpSurface.cookieName(req, family) + '=' + handle +
      '; Path=' + MockRpSurface.appPath(family) + '; Max-Age=' +
      Math.max(0, Math.floor(maxAgeS)) + '; HttpOnly; SameSite=Lax' +
      (req && req.secure ? '; Secure' : '');
    if (res && typeof res.append === 'function') {
      res.append('Set-Cookie', line);
    } else if (res && typeof res.setHeader === 'function') {
      const had = typeof res.getHeader === 'function'
        ? res.getHeader('Set-Cookie') : null;
      const list = Array.isArray(had) ? had : (had ? [String(had)] : []);
      res.setHeader('Set-Cookie', list.concat([line]));
    }
    log.debug("Leaving MockRpSurface.writeCookie().");
  }

  /**
   * The live session the request's cookie names in this realm, for this
   * family, or null. An expired one is dropped where it is found.
   *
   * @param req - the request
   * @param family - `wsfed`, `saml2` or `saml11`
   * @returns `{ key, session }`, or null
   */
  static held(req: Json, family: string): Json {
    log.debug("Entering MockRpSurface.held(). " + family);
    const handle = MockRpSurface.cookieOf(req, family);
    if (!handle) {
      log.debug("Leaving MockRpSurface.held(). No cookie.");
      return null;
    }
    const key = MockRpSurface.keyOf(handle);
    const session: MockRpSession = sessions.get(key);
    if (!session || session.family !== family) {
      sessionsCount.miss();
      log.debug("Leaving MockRpSurface.held(). None by that cookie.");
      return null;
    }
    if (sessionExpired(session, Date.now())) {
      sessions.delete(key);
      sessionsCount.miss();
      log.debug("Leaving MockRpSurface.held(). Expired.");
      return null;
    }
    sessionsCount.hit();
    log.debug("Leaving MockRpSurface.held().");
    return { key: key, session: session };
  }

  /**
   * Opens a new session and writes its cookie.
   *
   * @param req - the request
   * @param res - the response
   * @param family - `wsfed`, `saml2` or `saml11`
   * @param fields - what it holds: `signedIn`, `flash` and the subject's
   * names
   * @returns nothing
   */
  static open(req: Json, res: Json, family: string, fields: Json): void {
    log.debug("Entering MockRpSurface.open(). " + family);
    const now = Date.now();
    const ttl = MockRpSurface.sessionTtlMs(family);
    const handle = helpers.randomId(32);
    const key = MockRpSurface.keyOf(handle);
    cacheRegistry.makeRoom(sessions, MAX_SESSIONS, {
      expired: function (value: Json): boolean {
        return sessionExpired(value, Date.now());
      },
      counter: sessionsCount, name: 'mockRp.sessions' });
    const session: MockRpSession = {
      family: family, created: now, expires: now + ttl,
      signedIn: fields.signedIn || null, flash: fields.flash || null,
      subject: String(fields.subject || ''),
      nameIdFormat: String(fields.nameIdFormat || ''),
      sessionIndex: String(fields.sessionIndex || '')
    };
    sessions.set(key, session);
    MockRpSurface.writeCookie(req, res, family, handle, ttl / 1000);
    log.debug("Leaving MockRpSurface.open().");
  }

  /**
   * A response that passed every check: the session the browser held here
   * is ended, a new one opened holding the verdict, and the browser sent on
   * to the family's application page with a 303 — POST, redirect, GET.
   *
   * @param req - the request
   * @param res - the response
   * @param family - `wsfed`, `saml2` or `saml11`
   * @param view - the verdict's facts
   * @param subject - `{ subject, nameIdFormat, sessionIndex }`
   * @param location - where to send the browser; the application page
   * where left out
   * @returns nothing
   */
  static signIn(req: Json, res: Json, family: string, view: Json,
                subject: Json, location?: string): void {
    log.debug("Entering MockRpSurface.signIn(). " + family);
    const had = MockRpSurface.held(req, family);
    if (had) {
      // ROTATED, as a real relying party rotates its session at a sign-in.
      sessions.delete(had.key);
    }
    MockRpSurface.open(req, res, family, Object.assign({ signedIn: view },
                                                       subject || {}));
    // error-code: none — a sign-in that passed every check.
    res.set('Cache-Control', 'no-store')
       .redirect(303, location || MockRpSurface.appPath(family));
    log.debug("Leaving MockRpSurface.signIn().");
  }

  /**
   * Holds a refusal (or an outcome) for the application page to read once:
   * on the live session the browser already has here, which it leaves as it
   * is, or on a new session that holds nothing else.
   *
   * @param req - the request
   * @param res - the response
   * @param family - `wsfed`, `saml2` or `saml11`
   * @param view - the refusal's facts
   * @returns nothing
   */
  static hold(req: Json, res: Json, family: string, view: Json): void {
    log.debug("Entering MockRpSurface.hold(). " + family);
    const had = MockRpSurface.held(req, family);
    if (had) {
      sessions.set(had.key, Object.assign({}, had.session, { flash: view }));
      log.debug("Leaving MockRpSurface.hold(). On the live session.");
      return;
    }
    MockRpSurface.open(req, res, family, { flash: view });
    log.debug("Leaving MockRpSurface.hold(). On a new session.");
  }

  /**
   * A response that did not pass: no session is opened, the refusal is held
   * for the page, and the answer is the receiving door's own status — the
   * shell, which asks the session view. The caller marked the code.
   *
   * @param req - the request
   * @param res - the response
   * @param status - the receiving door's status
   * @param family - `wsfed`, `saml2` or `saml11`
   * @param view - the refusal's facts
   * @returns nothing
   */
  static refuse(req: Json, res: Res, status: number, family: string,
                view: Json): void {
    log.debug("Entering MockRpSurface.refuse(). " + family + " " + status);
    MockRpSurface.hold(req, res, family, view);
    MockRpSurface.sendShell(req, res, status, family);
    log.debug("Leaving MockRpSurface.refuse().");
  }

  /**
   * Ends the session the request's cookie names, and clears the cookie.
   *
   * @param req - the request
   * @param res - the response
   * @param family - `wsfed`, `saml2` or `saml11`
   * @returns the session that ended, or null
   */
  static end(req: Json, res: Json, family: string): Json {
    log.debug("Entering MockRpSurface.end(). " + family);
    const had = MockRpSurface.held(req, family);
    if (MockRpSurface.cookieOf(req, family)) {
      MockRpSurface.writeCookie(req, res, family, '', 0);
    }
    if (!had) {
      log.debug("Leaving MockRpSurface.end(). None held.");
      return null;
    }
    sessions.delete(had.key);
    log.debug("Leaving MockRpSurface.end().");
    return had.session;
  }

  /**
   * Ends every signed-in session of the family in this realm that a
   * logout message names — the way a real relying party finds them, by what
   * the message carries rather than by a cookie the identity provider's
   * request may not bring.
   *
   * @param family - `wsfed`, `saml2` or `saml11`
   * @param names - `(session) => boolean`
   * @returns how many ended
   */
  static endWhere(family: string,
                  names: (session: MockRpSession) => boolean): number {
    log.debug("Entering MockRpSurface.endWhere(). " + family);
    const ending: string[] = [];
    sessions.forEach(function (value: MockRpSession, key: string) {
      if (value && value.family === family && value.signedIn &&
          names(value)) {
        ending.push(key);
      }
    });
    ending.forEach(function (key) {
      sessions.delete(key);
    });
    log.debug("Leaving MockRpSurface.endWhere(). " + ending.length +
              " ended.");
    return ending.length;
  }

  /**
   * The application page's question: what the session holds. A refusal or
   * an outcome is answered once and then dropped (and the session with it,
   * where it held nothing else); a signed-in session's verdict is answered
   * for as long as it lives.
   *
   * @param req - the request
   * @param res - the response
   * @param family - `wsfed`, `saml2` or `saml11`
   * @returns `{ ok, view }`, the view null where there is nothing
   */
  static sessionView(req: Json, res: Json, family: string): Json {
    log.debug("Entering MockRpSurface.sessionView(). " + family);
    const had = MockRpSurface.held(req, family);
    if (!had) {
      if (MockRpSurface.cookieOf(req, family)) {
        MockRpSurface.writeCookie(req, res, family, '', 0);
      }
      log.debug("Leaving MockRpSurface.sessionView(). None.");
      return { ok: true, view: null };
    }
    const session: MockRpSession = had.session;
    const signedIn = !!session.signedIn;
    const about = { signedIn: signedIn, subject: session.subject,
                    expires: new Date(session.expires).toISOString(),
                    signOut: MockRpSurface.signOutPath(family) };
    if (session.flash) {
      if (signedIn) {
        sessions.set(had.key, Object.assign({}, session, { flash: null }));
      } else {
        sessions.delete(had.key);
        MockRpSurface.writeCookie(req, res, family, '', 0);
      }
      log.debug("Leaving MockRpSurface.sessionView(). The held refusal.");
      return { ok: true, view: Object.assign({}, session.flash,
                                             { session: about }) };
    }
    log.debug("Leaving MockRpSurface.sessionView(). Signed in.");
    return { ok: true, view: Object.assign({}, session.signedIn,
                                           { session: about }) };
  }

  /**
   * Registers a family's script, start view, session view and sign-out, all
   * marked as a demonstration. The start view is what `hooks.start(req)`
   * answers; the sign-out ends the session and sends the browser where
   * `hooks.signOut(req, ended)` says — the identity provider's sign-out,
   * where the family has one — or to the application page.
   *
   * @param app - the express app
   * @param family - `wsfed`, `saml2` or `saml11`
   * @param hooks - `{ start(req), signOut?(req, ended) }`
   * @returns nothing
   */
  static registerRoutes(app: Json, family: string, hooks: Json): void {
    log.debug("Entering MockRpSurface.registerRoutes(). " + family);
    app.get(MockRpSurface.scriptPath(family), sharedApp.demoOnly,
            function (req: Req, res: Res) {
      log.debug("Entering the mock relying party's script. " + family);
      ShellDocument.sendFile(req, res, MockRpSurface.bundle(),
                             'application/javascript');
      log.debug("Leaving the mock relying party's script.");
    });
    app.get(MockRpSurface.startPath(family), sharedApp.demoOnly,
            function (req: Req, res: Res) {
      log.debug("Entering the mock relying party's start view. " + family);
      res.status(200).set('Cache-Control', 'no-store')
         .json({ ok: true, view: hooks.start(req) });
      log.debug("Leaving the mock relying party's start view.");
    });
    app.get(MockRpSurface.sessionPath(family), sharedApp.demoOnly,
            function (req: Req, res: Res) {
      log.debug("Entering the mock relying party's session view. " +
                family);
      const answer = MockRpSurface.sessionView(req, res, family);
      res.status(200).set('Cache-Control', 'no-store').json(answer);
      log.debug("Leaving the mock relying party's session view.");
    });
    app.post(MockRpSurface.signOutPath(family), sharedApp.demoOnly,
             function (req: Req, res: Res) {
      log.debug("Entering the mock relying party's sign-out. " + family);
      const ended = MockRpSurface.end(req, res, family);
      const to = typeof hooks.signOut === 'function'
        ? hooks.signOut(req, ended) : '';
      // error-code: none — a sign-out, which ends whatever it finds.
      res.set('Cache-Control', 'no-store')
         .redirect(303, to || MockRpSurface.appPath(family));
      log.debug("Leaving the mock relying party's sign-out. " +
                (ended ? 'Ended.' : 'Nothing held.'));
    });
    log.debug("Leaving MockRpSurface.registerRoutes().");
  }
}

export = MockRpSurface;
