// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: realm_chooser.ts
//
// ---------------------------------------------------------------------------
// WHICH REALM TO SIGN IN THROUGH (2026-09-14, ticket #32).
//
// Since #32 a trust realm has administrators of its own, and the admin console
// and the user portal sign a person in through the realm they are reached in —
// `/realm/acme/admin` authenticates against acme's directory and asks acme's
// roster. A person who opens the plain `/admin` or `/portal` of a service with
// realms defined therefore has a question to answer before a sign-in screen
// means anything: WHICH realm are they? This module asks it, for both
// surfaces, so the two cannot come to ask it differently.
//
// **WHEN IT ASKS**, and every condition is what keeps something else working:
//
//   * a GET or HEAD of the surface's ROOT — exactly `/admin` or `/portal` — in
//     the DEFAULT realm, because a deep link already says where the reader was
//     going and a path under a realm prefix has already chosen;
//   * with no session for that surface, which the caller has already decided;
//   * with realms defined (`realms.active()`), because a service with none has
//     only one realm to choose and the page would be a click that does nothing;
//   * and with no `?realm=` — the choice itself, which is what the page's own
//     form submits and what a script or a test names to skip the page.
//
// **HOW IT ASKS** is a `common/mode.js` question: a list of every realm in
// development, a text box for the realm's id in product
// (`mode.listsRealmsBeforeSignIn()`).
//
// **A CHOICE IS A REDIRECT AND NEVER AN ECHO.** The id is looked up in the
// registry and the target is BUILT from the realm's own prefix, the surface's
// fixed root and the service's base — nothing from the request reaches the
// `Location` header, which is `/admin/realm-switch`'s rule for the same shape.
// The default realm's choice is not a redirect at all: the caller goes on to
// sign in right where it is.
//
// A LIBRARY (rule 3): no route. Each surface calls `decide()` from its own gate
// and draws `form()` in its own shell.
//
// ---------------------------------------------------------------------------
// THE FIRST MODULE CONVERTED TO TYPESCRIPT (#50, 2026-09-16), and the shape
// the rest follow:
//
//   * **A CLASS WITH ITS DEPENDENCIES PASSED TO ITS CONSTRUCTOR.** `realms`,
//     `mode`, the base-URL reader and the logger arrive as `RealmChooserDeps`,
//     so the composition root builds one and a test can build one with stubs.
//     Nothing here reaches for a module on its own.
//   * **THE MODULE STILL EXPORTS `SURFACES`, `decide` AND `form`**, from an
//     instance built with the real modules, because `admin-ui/admin.ts` and
//     `portal/portal.ts` are not converted and require it by those names. That
//     instance is TRANSITIONAL: it goes when the composition root
//     (`common/protocol_stack.ts`, which since #50's R1 registers the routes)
//     also constructs the modules and hands a `RealmChooser` to both surfaces
//     (#50's R2). `RealmChooser` is exported
//     beside it for that root.
//   * **`require` STAYS**, as `import x = require(...)`, which compiles to the
//     same `require` call (the require order is untouched).
// ---------------------------------------------------------------------------

import Html = require('./html');
import helpers = require('./helpers');
import realms = require('./realms');
import mode = require('./mode');
import InstanceSlot = require('./instance_slot');

// THE LANGUAGE (#539). A LIBRARY, as this module is (rule 3): `i18n`,
// `locale_policy`, `helpers` and `config`, and no route module.
import PageLocale = require('./page_locale');

type Translator = ReturnType<typeof PageLocale.forPage>;

type SurfaceId = 'admin' | 'portal';

interface Surface {
  root: string;
  label: string;
  // The hosted surface's own client_id, which is the application the page
  // is drawn for when its locale policy is asked (#539).
  application: string;
}

// What `decide()` answers when it has something to say. `null` means: sign
// in here, as before.
type Decision =
  | { kind: 'page'; error: string }
  | { kind: 'redirect'; location: string };

// The one realm field this module reads beyond its id.
interface RealmRow {
  id: string;
  name?: string;
}

// What a chooser needs from the rest of the service. Named for what is asked
// of each, so a test can supply exactly that and nothing more.
interface RealmChooserDeps {
  realms: {
    DEFAULT_ID: string;
    currentId(): string;
    currentPrefix(): string;
    active(): boolean;
    get(id: string): RealmRow | null | undefined;
    list(): RealmRow[];
    prefixOf(realm: RealmRow): string;
  };
  mode: { listsRealmsBeforeSignIn(): boolean };
  baseUrlOf(req: ChooserRequest): string;
  log: { debug(message: string): void };
}

// The parts of an express request this module reads.
interface ChooserRequest {
  method?: string;
  originalUrl?: string;
  query?: Record<string, unknown>;
}

/**
 * The two surfaces that ask which realm to sign in through, `admin` and
 * `portal`, each with its root path and the words the button uses.
 */
const SURFACES: Readonly<Record<SurfaceId, Surface>> = Object.freeze({
  admin: { root: '/admin', label: 'the admin console',
           application: 'sts-admin-console' },
  portal: { root: '/portal', label: 'your account',
            application: 'sts-user-portal' }
});

/**
 * Asks a person who opens the plain `/admin` or `/portal` of a service with
 * realms defined which realm they sign in through.
 *
 * In development it lists every realm; in product it asks for the realm's id
 * in a text box (`mode.listsRealmsBeforeSignIn()`).
 */
class RealmChooser {
  /**
   * The surfaces the chooser serves; the same object as the module's
   * `SURFACES`.
   */
  static readonly SURFACES = SURFACES;

  /**
   * Builds a chooser over its dependencies.
   *
   * @param deps - the realm registry, `mode`, the base-URL reader and a logger
   */
  constructor(private readonly deps: RealmChooserDeps) {
    deps.log.debug("Entering RealmChooser.constructor().");
    deps.log.debug("Leaving RealmChooser.constructor().");
  }

  // What the composition root passes, from the real modules; `helpers`
  // supplies both the logger and the base-URL reader, as it always did.
  /**
   * Returns the dependencies the composition root builds the chooser with.
   *
   * @returns the real `realms` and `mode`, and `helpers`' base-URL reader and
   *   logger
   */
  static defaultDeps(): RealmChooserDeps {
    helpers.log.debug("Entering RealmChooser.defaultDeps().");
    helpers.log.debug("Leaving RealmChooser.defaultDeps().");
    return { realms: realms, mode: mode, baseUrlOf: helpers.baseUrlOf,
             log: helpers.log };
  }

  // The service's own base with no realm prefix, whichever realm is ambient.
  private serviceRoot(req: ChooserRequest): string {
    const { log, realms, baseUrlOf } = this.deps;
    log.debug("Entering RealmChooser.serviceRoot().");
    const withRealm = baseUrlOf(req);
    const prefix = realms.currentPrefix();
    log.debug("Leaving RealmChooser.serviceRoot().");
    return prefix && withRealm.slice(-prefix.length) === prefix
      ? withRealm.slice(0, withRealm.length - prefix.length) : withRealm;
  }

  private queryRealm(req: ChooserRequest | null | undefined): string | null {
    const { log } = this.deps;
    log.debug("Entering RealmChooser.queryRealm().");
    const raw = req && req.query ? req.query.realm : undefined;
    const value = Array.isArray(raw) ? raw[0] : raw;
    log.debug("Leaving RealmChooser.queryRealm().");
    return value === undefined || value === null ? null : String(value).trim();
  }

  // -------------------------------------------------------------------------
  // THE DECISION. `surfaceId` is 'admin' or 'portal'; the caller has already
  // found no session. Answers:
  //
  //   null                              sign in here, as before
  //   { kind: 'page', error }           draw the chooser (with a sentence when
  //                                     the id asked for is not a realm)
  //   { kind: 'redirect', location }    the realm chosen, under its own prefix
  // -------------------------------------------------------------------------
  /**
   * Decides whether a request for a surface's root must first choose a realm.
   *
   * It asks only for a GET or HEAD of exactly the surface's root in the default
   * realm, with realms defined; the caller has already found no session. A
   * choice is a redirect built from the registry's own prefix, never an echo of
   * the request.
   * @param req - the express request
   * @param surfaceId - 'admin' or 'portal'
   * @returns null to sign in here; `{ kind: 'page', error }` to draw the
   *   chooser (with a sentence when the id asked for is no realm); or
   *   `{ kind: 'redirect', location }` to the chosen realm's surface
   */
  decide(req: ChooserRequest | null | undefined,
         surfaceId: string): Decision | null {
    const { log, realms } = this.deps;
    log.debug("Entering RealmChooser.decide(). surface=" + surfaceId);
    const surface: Surface | undefined = SURFACES[surfaceId as SurfaceId];
    const method = String((req && req.method) || 'GET').toUpperCase();
    const path = String((req && req.originalUrl) || '').split('?')[0]
      .replace(/\/+$/, '');
    if (!surface || (method !== 'GET' && method !== 'HEAD') ||
        realms.currentId() !== realms.DEFAULT_ID || !realms.active() ||
        path !== surface.root) {
      log.debug("Leaving RealmChooser.decide(). Not the chooser's question.");
      return null;
    }
    const asked = this.queryRealm(req);
    if (asked === null) {
      log.debug("Leaving RealmChooser.decide(). Draw the chooser.");
      return { kind: 'page', error: '' };
    }
    if (!asked || asked === realms.DEFAULT_ID) {
      log.debug("Leaving RealmChooser.decide(). The default realm; sign in " +
                "here.");
      return null;
    }
    const realm = realms.get(asked);
    if (!realm || realm.id === realms.DEFAULT_ID) {
      log.debug("Leaving RealmChooser.decide(). No such realm.");
      return { kind: 'page',
               error: 'There is no realm with the id "' + asked.slice(0, 64) +
                      '". Check the id and try again.' };
    }
    const location = this.serviceRoot(req || {}) + realms.prefixOf(realm) +
      surface.root;
    log.debug("Leaving RealmChooser.decide(). To " + location + ".");
    return { kind: 'redirect', location: location };
  }

  // The form, as a fragment for the surface's own page. No script: a list or a
  // text box and a real submit button, posting nothing — a GET of the surface's
  // root carrying `realm`, which `decide()` answers.
  /**
   * Draws the chooser as an HTML fragment for the surface's own page: a list or
   * a text box and a submit button, a GET of the surface's root with `realm`.
   *
   * @param req - the express request
   * @param surfaceId - 'admin' or 'portal'
   * @param error - optional sentence to show above the form
   * @param translator - the page's translator; built here when not given
   * @returns the HTML fragment
   */
  form(req: ChooserRequest, surfaceId: string, error?: string,
       translator?: Translator): string {
    const { log, realms, mode } = this.deps;
    log.debug("Entering RealmChooser.form(). surface=" + surfaceId);
    const surface = SURFACES[surfaceId as SurfaceId] || SURFACES.admin;
    // THE LANGUAGE (#539): nobody has signed in yet, so the person is not
    // known; the application is the surface. The error stays English.
    const t = translator ||
      PageLocale.forPage({ application: surface.application });
    // Which surface, as the messages' `select` reads it: `surface.label` is
    // English, so the words are chosen in the catalog by the surface's id.
    const which = surface === SURFACES.portal ? 'portal' : 'admin';
    const action = this.serviceRoot(req) + surface.root;
    const listed = mode.listsRealmsBeforeSignIn();
    const control = listed
      ? '<select id="realmchoice" name="realm" autofocus>' +
        realms.list().map(function (realm) {
          return '<option value="' + Html.esc(realm.id) + '">' +
            Html.esc(realm.name) +
            (realm.id === realms.DEFAULT_ID
              ? ' ' + t.html('realmChooser.defaultRealm') : '') +
            '</option>';
        }).join('') + '</select>'
      : '<input type="text" id="realmchoice" name="realm" size="28" ' +
        'autocomplete="organization" placeholder="' +
        Html.esc(realms.DEFAULT_ID) + '" required autofocus>';
    log.debug("Leaving RealmChooser.form(). " +
              (listed ? "A list." : "A text box."));
    return (error ? '<div class="err">' + Html.esc(error) + '</div>' : '') +
      '<p>' + t.html('realmChooser.explain') + '</p>' +
      '<form method="get" action="' + Html.esc(action) + '">' +
      '<p><label for="realmchoice">' + t.html('realmChooser.realm') +
      '</label> ' + control + ' ' +
      '<button type="submit">' +
      t.html('realmChooser.continue', { surface: which }) +
      '</button></p></form>' +
      (listed ? ''
        : '<p class="note">' +
          t.html('realmChooser.idNote', { id: realms.DEFAULT_ID }) + '</p>');
  }

  // THE CHOOSER AS A PAGE OF ITS OWN (2026-10-08, rcbj). Both surfaces drew
  // the form inside their own frame — the console's sidebar, account menu
  // and refresh, the portal's navigation — and every one of those controls
  // led to a sign-in this page had not let the reader start, so the first
  // thing a visitor saw was a console with nothing in it and a small form
  // that was the only thing on it that worked. So the page is the question
  // and nothing else: a blank, centred document holding a large control (a
  // list in development, the realm's id in product — #32's rule, unchanged)
  // and its button. No script and no stylesheet but its own: everything a
  // frame would add here is a control that cannot be used yet.
  /**
   * Draws the chooser as a complete HTML document of its own: a heading, a
   * note saying a realm must be chosen first, and the form, centred and large,
   * with nothing of either surface's frame around it.
   *
   * @param req - the express request
   * @param surfaceId - 'admin' or 'portal'
   * @param error - optional sentence to show above the form
   * @returns the HTML document
   */
  page(req: ChooserRequest, surfaceId: string, error?: string): string {
    const { log, realms } = this.deps;
    log.debug("Entering RealmChooser.page(). surface=" + surfaceId);
    const surface = SURFACES[surfaceId as SurfaceId] || SURFACES.admin;
    const which = surface === SURFACES.portal ? 'portal' : 'admin';
    // THE LANGUAGE (#539), as form()'s: the surface is the application.
    const t = PageLocale.forPage({ application: surface.application });
    const style =
      ':root{--bg:#f4f4f7;--card:#fff;--ink:#1f2330;--muted:#5b6070;' +
      '--line:#d5d5dd;--accent:#4b3fa7;--accent-ink:#fff;--err:#a3242c;' +
      '--err-bg:#fbeaea}' +
      '@media (prefers-color-scheme:dark){:root{--bg:#15161b;' +
      '--card:#1f2129;--ink:#e8e9ee;--muted:#a3a7b5;--line:#3a3d4a;' +
      '--accent:#8f84f0;--accent-ink:#15161b;--err:#ff9ca2;' +
      '--err-bg:#3a1d20}}' +
      '*{box-sizing:border-box}' +
      'body{margin:0;min-height:100vh;display:flex;align-items:center;' +
      'justify-content:center;background:var(--bg);color:var(--ink);' +
      'font-family:system-ui,-apple-system,"Segoe UI",Arial,sans-serif;' +
      'padding:16px}' +
      '.chooser{background:var(--card);border:1px solid var(--line);' +
      'border-radius:14px;padding:36px 40px;width:100%;max-width:34rem;' +
      'box-shadow:0 8px 32px rgba(0,0,0,.08);text-align:center}' +
      '.chooser h1{font-size:1.7rem;margin:0 0 .4em}' +
      '.chooser .lead{font-size:1.1rem;margin:0 0 1.4em;color:var(--muted)}' +
      '.chooser form p{display:flex;flex-direction:column;gap:14px;' +
      'margin:1.2em 0}' +
      '.chooser label{font-weight:600;font-size:1.05rem}' +
      '.chooser select,.chooser input{font-size:1.35rem;padding:.6em .7em;' +
      'border:2px solid var(--accent);border-radius:10px;width:100%;' +
      'background:var(--card);color:var(--ink)}' +
      '.chooser button{font-size:1.25rem;padding:.7em 1em;border:0;' +
      'border-radius:10px;background:var(--accent);color:var(--accent-ink);' +
      'cursor:pointer;width:100%}' +
      '.chooser button:focus-visible,.chooser select:focus-visible,' +
      '.chooser input:focus-visible{outline:3px solid var(--accent);' +
      'outline-offset:3px}' +
      '.chooser .note,.chooser>p{color:var(--muted);font-size:.95rem}' +
      '.chooser .err{background:var(--err-bg);color:var(--err);' +
      'border-radius:8px;padding:.7em 1em;margin:0 0 1em;text-align:left}' +
      // The language chooser is small and sits above the question; it is the
      // one other control that works before a realm is chosen.
      '.chooser form.language-chooser{font-size:.85rem;color:var(--muted);' +
      'margin:0 0 1em}' +
      '.chooser form.language-chooser select,' +
      '.chooser form.language-chooser button{font-size:.85rem;width:auto;' +
      'padding:.2em .5em;border-width:1px;border-radius:6px}' +
      '.chooser form.language-chooser button{background:var(--card);' +
      'color:var(--ink);border:1px solid var(--line)}';
    const html = '<!DOCTYPE html><html' + PageLocale.htmlAttributes(t) +
      '><head>' +
      '<meta charset="utf-8">' +
      '<meta name="viewport" content="width=device-width, initial-scale=1">' +
      '<title>' + Html.esc(t.text('realmChooser.title')) +
      '</title><style>' + style + '</style></head>' +
      '<body><main class="chooser">' +
      // Drawn only for a GET or HEAD of the surface's root, which redraws it.
      PageLocale.chooser(t, realms.currentPrefix(),
        PageLocale.herePath(realms.currentPrefix() + surface.root)) +
      '<h1>' + t.html('realmChooser.heading') + '</h1>' +
      '<p class="lead">' + t.html('realmChooser.lead', { surface: which }) +
      '</p>' + this.form(req, surfaceId, error, t) +
      '</main></body></html>';
    log.debug("Leaving RealmChooser.page().");
    return html;
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds no
// instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that instance, for
// the JavaScript that still calls this module through `require()`; a process
// that never runs the root gets a default instance, built from
// `defaultDeps()` on first use (see `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<RealmChooser>(
  'common/realm_chooser',
  () => new RealmChooser(RealmChooser.defaultDeps()),
  null,
  helpers.log);

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

/**
 * Which realm to sign in through, asked for both the admin console and the
 * user portal so the two cannot ask it differently.
 *
 * A library: no route. `decide` and `form` forward to the instance the
 * composition root installs.
 * @namespace
 */
export = {
  RealmChooser: RealmChooser,
  SURFACES: SURFACES,
  /**
   * Installs the chooser the composition root built.
   */
  installInstance: (instance: RealmChooser): void => slot.install(instance),
  /**
   * Names where the installed chooser came from.
   */
  instanceOrigin: (): string => slot.origin(),
  decide: slot.forward('decide'),
  form: slot.forward('form'),
  page: slot.forward('page')
};
