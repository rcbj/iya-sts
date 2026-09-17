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

type SurfaceId = 'admin' | 'portal';

interface Surface {
  root: string;
  label: string;
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

const SURFACES: Readonly<Record<SurfaceId, Surface>> = Object.freeze({
  admin: { root: '/admin', label: 'the admin console' },
  portal: { root: '/portal', label: 'your account' }
});

class RealmChooser {
  static readonly SURFACES = SURFACES;

  constructor(private readonly deps: RealmChooserDeps) {
    deps.log.debug("Entering RealmChooser.constructor().");
    deps.log.debug("Leaving RealmChooser.constructor().");
  }

  // What the composition root passes, from the real modules; `helpers`
  // supplies both the logger and the base-URL reader, as it always did.
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
  form(req: ChooserRequest, surfaceId: string, error?: string): string {
    const { log, realms, mode } = this.deps;
    log.debug("Entering RealmChooser.form(). surface=" + surfaceId);
    const surface = SURFACES[surfaceId as SurfaceId] || SURFACES.admin;
    const action = this.serviceRoot(req) + surface.root;
    const listed = mode.listsRealmsBeforeSignIn();
    const control = listed
      ? '<select id="realmchoice" name="realm">' +
        realms.list().map(function (realm) {
          return '<option value="' + Html.esc(realm.id) + '">' +
            Html.esc(realm.name) +
            (realm.id === realms.DEFAULT_ID ? ' (the default realm)' : '') +
            '</option>';
        }).join('') + '</select>'
      : '<input type="text" id="realmchoice" name="realm" size="28" ' +
        'autocomplete="organization" placeholder="' +
        Html.esc(realms.DEFAULT_ID) + '" required>';
    log.debug("Leaving RealmChooser.form(). " +
              (listed ? "A list." : "A text box."));
    return (error ? '<div class="err">' + Html.esc(error) + '</div>' : '') +
      '<p>This service hosts more than one trust realm, and each has its own ' +
      'people and its own administrators. Choose the realm you belong to, ' +
      'and you will be asked to sign in there.</p>' +
      '<form method="get" action="' + Html.esc(action) + '">' +
      '<p><label for="realmchoice">Realm</label> ' + control + ' ' +
      '<button type="submit">Continue to ' + Html.esc(surface.label) +
      '</button></p></form>' +
      (listed ? ''
        : '<p class="note">Your administrator can tell you the id of your ' +
          'realm. The default realm\'s id is <code>' +
          Html.esc(realms.DEFAULT_ID) + '</code>.</p>');
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

export = {
  RealmChooser: RealmChooser,
  SURFACES: SURFACES,
  installInstance: (instance: RealmChooser): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  decide: slot.forward('decide'),
  form: slot.forward('form')
};
