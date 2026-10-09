// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_answers.ts
//
// ---------------------------------------------------------------------------
// WHAT A FORM'S ANSWER DRAWS, WHERE A NOTICE IS NOT ENOUGH (#446, 2026-10-05).
//
// Most of the console's forms are one act whose answer is a sentence: the
// runtime sends the form to its operation and draws the page again with that
// sentence in the strip, which is what `respondToAction()`'s 303 did. The
// server-rendered console answered three other kinds of form with a PAGE, in
// the handlers the cutover deleted, and each of them is here, drawn from the
// operation's answer and nothing else:
//
//   1. **A SECRET SHOWN ONCE.** A generated password, a reset or activation
//      link, an app password, a realm's bootstrap password, a keytab, an EAB
//      key, a SCEP challenge, a private key (a DID key, an RFC 8705 client
//      certificate, a person's assertion key, a remote PEP's listener). A
//      redirect would carry it on a query string — the browser history, the
//      access log, the next request's `Referer` — so each was a 200 page,
//      `no-store`, and here it is drawn in place: never on a URL, never in
//      the history, gone when the reader moves on. `once()`.
//   2. **A ROUND TRIP THAT WRITES NOTHING.** A field grid's "+" and bin, the
//      new-user and new-application forms' view switch: the form posted to
//      itself and came back with one box more or fewer and every other box
//      as it was. Each of those forms' hidden `action` is the write (`create`,
//      `update-fields`), so sent to the operation such a press would MAKE
//      something; here it is drawn again from what the form holds, and
//      nothing is sent. `roundTrip()`.
//   3. **A REDRAW FROM AN ANSWER.** A refused create or edit comes back to
//      its form with every box as it was and the reasons above it, rather
//      than to an empty form with a sentence; Fill, Generate secret and a
//      loaded RFC 9728 document put what they answered into the form; the
//      PKI workbench's buttons answer the workbench's next draft; an OpenID
//      Federation resolution is shown under the form that asked. `redraw()`.
//
// The renderers these pages are drawn by already took the state (`state`,
// `prefill`), because the server drew the same pages through them; this file
// builds that state from the form and the answer, which is what the deleted
// handlers did on the server.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// ---------------------------------------------------------------------------

import kit = require('./web_kit');

type Json = any;

// THE FORMS WHOSE BUTTONS ROUND-TRIP. The submitter's name is the press:
// `grow` and `drop` are the field grid's "+" and bin, `switchview` the
// simple / advanced switch. Every other submitter on these forms is the act.
const ROUND_TRIP_PAGES = ['/admin/users/new', '/admin/users/edit',
                          '/admin/applications/new',
                          '/admin/applications/edit'];
const ROUND_TRIP_NAMES = ['grow', 'drop', 'switchview'];

/**
 * Draws the answers a notice cannot carry.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class WebAnswers {
  /**
   * Whether a form field was posted.
   *
   * @param fields - the form's fields
   * @param name - the field
   * @returns true when it is present
   */
  static has(fields: Json, name: string): boolean {
    return !!fields && fields[name] !== undefined;
  }

  /**
   * One value of a form field, the last where it was posted more than once.
   *
   * @param fields - the form's fields
   * @param name - the field
   * @returns the value, or an empty string
   */
  static one(fields: Json, name: string): string {
    const value = fields ? fields[name] : undefined;
    if (Array.isArray(value)) {
      return String(value.length ? value[value.length - 1] : '');
    }
    return value === undefined || value === null ? '' : String(value);
  }

  /**
   * The values of a form field as a list.
   *
   * @param fields - the form's fields
   * @param name - the field
   * @returns the values
   */
  static many(fields: Json, name: string): string[] {
    const value = fields ? fields[name] : undefined;
    if (value === undefined || value === null) {
      return [];
    }
    return [].concat(value).map(String).filter(function (one) {
      return one !== '';
    });
  }

  // The protocol families a create form ticked, through the page's own
  // choices: a combined choice (`vc`) stands for the families it names, as
  // `applications.familiesOfChoices()` reads it on the server.
  /**
   * The protocol families a new-application form ticked.
   *
   * @param fields - the form's fields
   * @param json - the page's answer, with its `familyChoices`
   * @returns the families
   */
  static familiesOf(fields: Json, json: Json): string[] {
    const out = [];
    const choices = (json && json.familyChoices) || [];
    WebAnswers.many(fields, 'protocol')
      .concat(WebAnswers.many(fields, 'protocols'))
      .forEach(function (value) {
        const id = value.trim().toLowerCase();
        const row = choices.filter(function (one) {
          return one.id === id;
        })[0];
        const families = row && row.families && row.families.length
          ? row.families : [id];
        families.forEach(function (one) {
          if (one && out.indexOf(one) < 0) {
            out.push(one);
          }
        });
      });
    return out;
  }

  /**
   * A copy of an answer, so a redraw never edits the one in hand.
   *
   * @param json - the answer
   * @returns its copy
   */
  static copy(json: Json): Json {
    return JSON.parse(JSON.stringify(json || {}));
  }

  // A new-user form's values, put back: the boxes from the posted draft,
  // the username, the credential and the view. `newUserBody()` reads them
  // from `prefill`, and `username` and `credential` from the answer itself,
  // as `newUserJson(req, prefill)` put them there.
  /**
   * The new-user page's answer with what its form held put back.
   *
   * @param json - the page's answer
   * @param fields - the form's fields
   * @param view - the view to draw, `simple` or `advanced`
   * @returns the answer to draw
   */
  static newUserAgain(json: Json, fields: Json, view: string): Json {
    const out = WebAnswers.copy(json);
    out.username = WebAnswers.one(fields, 'username');
    out.credential = WebAnswers.one(fields, 'credential') ||
                     out.credential;
    out.prefill = { username: out.username, credential: out.credential,
                    fields: {}, view: view, draft: fields };
    return out;
  }

  // ---------------------------------------------------------------------------
  // 2. THE ROUND TRIPS
  // ---------------------------------------------------------------------------
  /**
   * Whether a press is a round trip that writes nothing.
   *
   * @param page - the console path the form posts to
   * @param fields - the form's fields, the submitter's among them
   * @returns true for "+", a bin and a view switch on the four field grids
   */
  static isRoundTrip(page: string, fields: Json): boolean {
    if (ROUND_TRIP_PAGES.indexOf(page) < 0) {
      return false;
    }
    return ROUND_TRIP_NAMES.some(function (name) {
      return WebAnswers.has(fields, name);
    });
  }

  /**
   * The page's answer drawn again after a round trip.
   *
   * @param page - the console path the form posts to
   * @param fields - the form's fields
   * @param json - the answer of the page in hand
   * @returns the answer to draw
   */
  static roundTrip(page: string, fields: Json, json: Json): Json {
    const switched = WebAnswers.has(fields, 'switchview')
      ? WebAnswers.one(fields, 'switchview') : WebAnswers.one(fields, 'view');
    if (page === '/admin/users/new') {
      return WebAnswers.newUserAgain(json, fields, switched);
    }
    const out = WebAnswers.copy(json);
    if (page === '/admin/applications/new') {
      const before = out.state || {};
      // A LOADED RFC 9728 DOCUMENT stays loaded: the server read the
      // original again for every redraw, and the page in hand already holds
      // what that reading answered.
      out.state = { loaded: before.loaded || null, draft: fields,
                    protocols: WebAnswers.familiesOf(fields, json),
                    view: switched,
                    tab: before.loaded ? 'fields' : undefined,
                    loadInput: before.loadInput };
      return out;
    }
    out.state = { draft: fields };
    return out;
  }

  // ---------------------------------------------------------------------------
  // 2a. A FIELD'S SEARCH (#459): the application page's Find, Previous,
  // Next and Add beside `appAllowedToDelegateTo`, `appAllowedToActOnBehalfOf`
  // (other applications) and `appDelegationSubjectGroup` (groups).
  //
  // THE FIELD GRID'S OWN MODEL, NOT A SECOND ONE. "+" and the bin are submit
  // buttons that draw the form again with every box kept; these are too, and
  // they differ only in that the redraw needs data — so the runtime asks
  // `GET /admin-api/applications` or `GET /admin-api/groups` (the lists the
  // Applications and Groups pages draw, rule 7: no console-only data path)
  // with `per=5`, and draws the answer under the box. Nothing is written: an
  // Add puts the value in a new box of the list, and the tab's Save writes
  // it, as it writes a box "+" made. These functions are pure, so the
  // parsing and the address are tested without a browser.
  // ---------------------------------------------------------------------------
  /**
   * Whether a press is one of a field search's buttons.
   *
   * @param page - the console path the form posts to
   * @param fields - the form's fields, the submitter's among them
   * @returns true for Find, Previous, Next and Add on an application's grid
   */
  static isFieldSearch(page: string, fields: Json): boolean {
    return page === '/admin/applications/edit' &&
      (WebAnswers.has(fields, 'fgsearch') || WebAnswers.has(fields, 'fgadd'));
  }

  // `fgsearch` is `<attribute>` (Find: page one) or `<attribute>|<page>`
  // (Previous, Next); `fgadd` is `<attribute>|<value>`. An attribute name
  // holds no `|`, so the FIRST one splits and a value may hold more.
  /**
   * Reads which search a press asks for.
   *
   * @param fields - the form's fields
   * @returns `{ attribute, which, query, page, add }`; `add` is '' unless
   *   Add (or Use)
   */
  static fieldSearchOf(fields: Json): Json {
    const pressed = WebAnswers.has(fields, 'fgadd')
      ? WebAnswers.one(fields, 'fgadd') : WebAnswers.one(fields, 'fgsearch');
    const bar = pressed.indexOf('|');
    const attribute = bar < 0 ? pressed : pressed.slice(0, bar);
    const rest = bar < 0 ? '' : pressed.slice(bar + 1);
    const adding = WebAnswers.has(fields, 'fgadd');
    const shown = Number(WebAnswers.one(fields, 'fgpage.' + attribute)) || 1;
    return {
      attribute: attribute,
      // WHICH KIND a `parties` search asks for (#461): the toggle's value,
      // people unless it says applications. Ignored by the other kinds.
      which: WebAnswers.one(fields, 'fgkind.' + attribute) === 'applications'
        ? 'applications' : 'people',
      query: WebAnswers.one(fields, 'fgfind.' + attribute).trim(),
      // An Add keeps the page it was pressed on; the answer is clamped, so a
      // page the Add emptied comes back as the last one.
      page: adding ? shown : Math.max(1, Math.floor(Number(rest)) || 1),
      add: adding ? rest : ''
    };
  }

  // A SINGLE-VALUED FIELD (#461) is one box, `field.<attribute>` with no
  // index, and the value REPLACES what it holds; a list gets a new box.
  /**
   * The form's fields with a value put in a new box of a list, after the
   * boxes it holds — or as they were when a box already holds it; for a
   * single-valued field, with the value in place of its one box's.
   *
   * @param fields - the form's fields
   * @param attribute - the list
   * @param value - the value
   * @returns the fields to draw
   */
  static withValueAdded(fields: Json, attribute: string,
                        value: string): Json {
    const out = Object.assign({}, fields);
    if (Object.prototype.hasOwnProperty.call(out, 'field.' + attribute)) {
      out['field.' + attribute] = value;
      return out;
    }
    const prefix = 'field.' + attribute + '.';
    let next = 0;
    let held = false;
    Object.keys(out).forEach(function (key) {
      if (key.indexOf(prefix) !== 0) {
        return;
      }
      const n = Number(key.slice(prefix.length));
      if (isFinite(n) && n >= next) {
        next = n + 1;
      }
      if (WebAnswers.one(out, key).trim() === value) {
        held = true;
      }
    });
    if (value && !held) {
      out[prefix + next] = value;
    }
    return out;
  }

  /**
   * The address of a field search's page of results.
   *
   * @param kind - `applications` or `groups`
   * @param asked - `fieldSearchOf()`'s answer
   * @param exclude - what to leave out: the application itself (for an
   *   application search) and what the list already holds
   * @returns the `/admin-api` path and query
   */
  static fieldSearchPath(kind: string, asked: Json, exclude: string[]): string {
    // `parties` (#461) asks one of two lists, as the toggle says: the
    // Users page's or the Applications page's. The users list takes no
    // `exclude`, and needs none: the one value is replaced, not added to.
    const people = kind === 'parties' && asked.which !== 'applications';
    const params = new URLSearchParams();
    if (asked.query) {
      params.append('q', asked.query);
    }
    params.append('per', String(kit.FIND_PER_PAGE));
    params.append('page', String(asked.page || 1));
    (people ? [] : exclude).forEach(function (one) {
      if (one) {
        params.append('exclude', one);
      }
    });
    return '/admin-api/' + (kind === 'groups' ? 'groups'
      : people ? 'users' : 'applications') + '?' + params.toString();
  }

  /**
   * A field search's results, as the grid draws them, from the list's
   * answer.
   *
   * @param kind - `applications`, `groups` or `parties`
   * @param asked - `fieldSearchOf()`'s answer
   * @param answer - the list operation's JSON, or null when it failed
   * @returns `{ kind, which, query, page, pages, matched, rows, failed }`,
   *   each row `{ value, label }` — and, for `parties`, `kind` (`person` or
   *   `application`), the value its entry's DN ('' where it has none)
   */
  static fieldSearchFound(kind: string, asked: Json, answer: Json): Json {
    const parties = kind === 'parties';
    const people = parties && asked.which !== 'applications';
    const list = kind === 'groups' ? 'groups' : people ? 'users'
      : 'applications';
    const ok = !!answer && Array.isArray(answer[list]);
    const rows = !ok ? [] : kind === 'groups'
      ? answer.groups.map(function (one) {
        return { value: String(one.dn), label: String(one.cn || '') };
      })
      : people
        ? answer.users.map(function (one) {
          return { kind: 'person', value: String(one.dn || ''),
                   label: String(one.name || one.key || '') };
        })
        : parties
          ? answer.applications.map(function (one) {
            return { kind: 'application', value: String(one.dn || ''),
                     label: String(one.identifier) +
                       (one.name && one.name !== one.identifier
                         ? ' (' + String(one.name) + ')' : '') };
          })
          : answer.applications.map(function (one) {
            return { value: String(one.identifier),
                     label: one.name && one.name !== one.identifier
                       ? String(one.name) : '' };
          });
    return { kind: kind, which: parties ? (people ? 'people'
                                                  : 'applications') : '',
             query: asked.query,
             page: ok ? Number(answer.page) || 1 : 1,
             pages: ok ? Number(answer.pages) || 1 : 1,
             matched: ok ? Number(answer.matched) || 0 : 0,
             rows: rows, failed: !ok };
  }

  // ---------------------------------------------------------------------------
  // 3. THE REDRAWS
  // ---------------------------------------------------------------------------
  /**
   * The page's answer drawn again from an act's answer, or null where the
   * act's sentence is all there is to draw.
   *
   * @param page - the console path the form posts to
   * @param action - the form's action
   * @param fields - the form's fields
   * @param answer - the operation's answer
   * @param json - the answer of the page in hand
   * @param t - optional; the translator (#539), the default when left out
   * @returns `{ json, banner }` to draw in place, or null
   */
  static redraw(page: string, action: string, fields: Json, answer: Json,
                json: Json, t?: Json): Json {
    t = t || kit.context().t;
    const ok = !!(answer && answer.ok);
    const errors = (answer && answer.errors) ||
      (answer && answer.why ? [String(answer.why)] : []);
    if (page === '/admin/users/new' && !ok) {
      return { json: WebAnswers.newUserAgain(json, fields,
                                             WebAnswers.one(fields, 'view')),
               banner: kit.warn('<strong>Nobody was created.</strong> ' +
                                kit.esc(errors.join(' ') || 'Refused.')) };
    }
    if (page === '/admin/users/edit' && !ok) {
      const out = WebAnswers.copy(json);
      out.state = { draft: fields, error: errors };
      return { json: out, banner: '' };
    }
    if (page === '/admin/applications/edit' && !ok) {
      const out = WebAnswers.copy(json);
      out.state = { draft: fields, error: errors };
      return { json: out, banner: '' };
    }
    if (page === '/admin/applications/new') {
      return WebAnswers.newApplicationRedraw(action, fields, answer, json, t);
    }
    if (page === '/admin/pki/certificate' && answer && answer.workbench) {
      // THE WORKBENCH'S NEXT DRAFT, refused or not: a refusal that drew the
      // form empty would be worse than the refusal.
      const out = WebAnswers.copy(json);
      out.workbench = answer.workbench;
      // A success's fallback word is translated; a refusal's words are the
      // server's, in English.
      const message = ok ? String(answer.why || answer.message ||
                                  t.text('consoleAnswers.done'))
        : errors.join(' ');
      return { json: out,
               banner: ok ? kit.note(kit.esc(message))
                          : kit.warn(kit.esc(message), 'That was refused') };
    }
    if (page === '/admin/oidfed' && ok && answer.resolution) {
      const out = WebAnswers.copy(json);
      out.resolution = answer.resolution;
      return { json: out, banner: kit.note(kit.esc(answer.message || '')) };
    }
    return null;
  }

  // The new-application form's three answers that put something into the
  // form rather than writing: a loaded RFC 9728 document, a generated
  // secret, and a refused create.
  /**
   * The new-application page drawn again from an act's answer.
   *
   * @param action - the form's action
   * @param fields - the form's fields
   * @param answer - the operation's answer
   * @param json - the answer of the page in hand
   * @param t - optional; the translator (#539), the default when left out
   * @returns `{ json, banner }`, or null
   */
  static newApplicationRedraw(action: string, fields: Json, answer: Json,
                              json: Json, t?: Json): Json {
    t = t || kit.context().t;
    const ok = !!(answer && answer.ok);
    const errors = (answer && answer.errors) || [];
    const out = WebAnswers.copy(json);
    const before = out.state || {};
    if (action === 'load-resource-metadata') {
      out.state = ok
        ? { loaded: answer, loadInput: { url: answer.url } }
        : { loadError: true, error: errors,
            errorTitle: 'The protected resource metadata was not loaded.',
            loadInput: { document: WebAnswers.one(fields, 'document'),
                         url: WebAnswers.one(fields, 'url') } };
      return { json: out, banner: '' };
    }
    if (action === 'generate-secret' && ok) {
      // The secret into its box, and the method a secret is presented by
      // where nothing (or `none`) was ticked: RFC 7591 section 2's default.
      const draft = Object.assign({}, fields, {
        'field.oauthClientSecret': answer.clientSecret });
      const methodKeys = Object.keys(fields).filter(function (key) {
        return /^field\.oauthTokenEndpointAuthMethod(\.\d+)?$/.test(key);
      });
      const asked = methodKeys.filter(function (key) {
        const value = WebAnswers.one(fields, key).trim();
        return value !== '' && value !== 'none';
      });
      if (!asked.length) {
        methodKeys.forEach(function (key) {
          delete draft[key];
        });
        draft['field.oauthTokenEndpointAuthMethod.0'] = 'client_secret_basic';
      }
      out.state = { loaded: before.loaded || null, draft: draft,
                    protocols: WebAnswers.familiesOf(fields, json),
                    view: WebAnswers.one(fields, 'view'),
                    tab: before.loaded ? 'fields' : undefined,
                    loadInput: before.loadInput,
                    // TEXT: the page escapes it where it draws it.
                    notice: t.text('consoleAnswers.secretGenerated') };
      return { json: out, banner: '' };
    }
    if (action === 'create' && !ok) {
      out.state = { loaded: before.loaded || null, draft: fields,
                    protocols: WebAnswers.familiesOf(fields, json),
                    view: WebAnswers.one(fields, 'view'),
                    tab: before.loaded ? 'fields' : undefined,
                    loadInput: before.loadInput,
                    error: errors.length ? errors
                      : [String((answer && answer.why) || 'Refused.')],
                    errorTitle: 'The application was not created.' };
      return { json: out, banner: '' };
    }
    return null;
  }

  // Fill on the new-user form (development only): the invented person for
  // the username typed, put into every box nobody has typed in — what was
  // typed is never overwritten, so pressing it twice loses nothing.
  /**
   * The new-user page filled from the invented person.
   *
   * @param fields - the form's fields
   * @param answer - `GET /admin-api/users/new?invent=` answered
   * @param json - the answer of the page in hand
   * @param t - optional; the translator (#539), the default when left out
   * @returns `{ json, banner }`
   */
  static filled(fields: Json, answer: Json, json: Json, t?: Json): Json {
    t = t || kit.context().t;
    const username = WebAnswers.one(fields, 'username').trim();
    if (!answer || !answer.invented) {
      return { json: WebAnswers.newUserAgain(json, fields,
                                             WebAnswers.one(fields, 'view')),
               banner: kit.warn(kit.esc((answer && answer.inventRefused) ||
                 'Nothing was filled in.')) };
    }
    const posted = kit.gridValuesFromDraft(fields, json.longTextAttributes);
    const merged = {};
    Object.keys(answer.invented).forEach(function (name) {
      merged[name] = [].concat(answer.invented[name]).map(String);
    });
    Object.keys(posted).forEach(function (name) {
      const typed = (posted[name] || []).filter(function (one) {
        return String(one) !== '';
      });
      if (typed.length) {
        merged[name] = typed;
      }
    });
    const out = WebAnswers.newUserAgain(json, fields,
                                        WebAnswers.one(fields, 'view'));
    out.prefill.draft = null;
    out.prefill.fields = merged;
    return { json: out,
             banner: '<div class="ok">' +
               t.html('consoleAnswers.filled', { username: username }) +
               '</div>' };
  }

  // ---------------------------------------------------------------------------
  // WHERE AN ACT LANDS, WHERE IT IS NOT THE PAGE ITS FORM WAS ON (#446).
  //
  // The server-rendered console's handlers each chose a target, and two sent
  // the reader somewhere the form was not: a new APPLICATION is looked at
  // next, on its own drill-down rather than an empty create form, and a
  // GROUP acted on lands on that group — a create on the group it made,
  // because the next thing anybody does with a new group is put somebody in
  // it and the Add member control is on the drill-down. A refusal stays put,
  // beside the form that produced it. Every other act goes back to its
  // page (`ConsoleRuntime.submit()`).
  // ---------------------------------------------------------------------------
  /**
   * The console path an act's answer is drawn on, where it is not `back`.
   *
   * @param page - the console path the form posts to
   * @param action - the form's action
   * @param answer - the operation's answer
   * @param back - the page and list view the form was on
   * @returns the path and query, without the notice, or null for `back`
   */
  static landing(page: string, action: string, answer: Json,
                 back: string): string | null {
    if (!answer || !answer.ok) {
      return null;
    }
    const at = new URL(back, 'https://console.invalid');
    if (page === '/admin/applications/new' && action === 'create' &&
        answer.application && answer.application.identifier) {
      return '/admin/applications?' + new URLSearchParams({
        application: String(answer.application.identifier) }).toString();
    }
    if (page === '/admin/groups' && answer.dn &&
        (action === 'create' || action === 'add-member')) {
      at.searchParams.set('group', String(answer.dn));
      return '/admin/groups?' + at.searchParams.toString();
    }
    return null;
  }

  // ---------------------------------------------------------------------------
  // 1. THE SECRETS SHOWN ONCE
  // ---------------------------------------------------------------------------
  /**
   * The page an answer carrying a secret is drawn as, or null.
   *
   * @param page - the console path the form posts to
   * @param action - the form's action
   * @param fields - the form's fields
   * @param answer - the operation's answer
   * @param env - `base` (this realm's absolute root, for a link somebody
   *   will paste) and `back` (the page the form was on)
   * @param t - optional; the translator (#539), the default when left out
   * @returns `{ title, active, html }`, or null
   */
  static once(page: string, action: string, fields: Json, answer: Json,
              env: Json, t?: Json): Json {
    if (!answer || !answer.ok) {
      return null;
    }
    t = t || kit.context().t;
    const back = String((env && env.back) || '/admin');
    if (page === '/admin/users/new' && action === 'create') {
      return { title: t.text('consoleAnswers.once.userCreated'),
               active: '/admin/users',
               html: WebAnswers.createdUser(answer, env, t) };
    }
    if (answer.keytab) {
      return { title: t.text('consoleAnswers.once.keytab'),
               active: answer.username ? '/admin/users'
                                       : '/admin/kerberos/principals',
               html: WebAnswers.keytab(answer, t) };
    }
    if (page === '/admin/users' &&
        (answer.password || answer.resetUrl || answer.appPassword)) {
      return { title: t.text('consoleAnswers.once.credentialReset'),
               active: '/admin/users',
               html: WebAnswers.credentialReset(answer, back, t) };
    }
    if (page === '/admin/realms' && answer.password) {
      return { title: t.text('consoleAnswers.once.realmCreated'),
               active: '/admin/realms',
               html: WebAnswers.realmCreated(answer, env, t) };
    }
    if (answer.hmacKey) {
      return { title: t.text('consoleAnswers.once.eabKey'),
               active: '/admin/acme',
               html: WebAnswers.eabKey(answer, back, t) };
    }
    if (answer.challenge && page === '/admin/scep') {
      return { title: t.text('consoleAnswers.once.scep'),
               active: '/admin/scep',
               html: WebAnswers.scepChallenge(answer, back, t) };
    }
    if (page === '/admin/applications' && action === 'generate-did-key' &&
        answer.privateJwk) {
      return { title: t.text('consoleAnswers.once.didKey'),
               active: '/admin/applications',
               html: WebAnswers.didKey(answer, fields, back, t) };
    }
    if (page === '/admin/applications' &&
        action === 'issue-tls-client-certificate' && answer.files) {
      return { title: t.text('consoleAnswers.once.tlsClientCertificate'),
               active: '/admin/applications',
               html: WebAnswers.tlsClientCertificate(answer, fields, back,
                                                     t) };
    }
    if (page === '/admin/xacml/peps' &&
        action === 'issue-pep-certificate' && answer.privateKeyPem) {
      return { title: t.text('consoleAnswers.once.pepCertificate'),
               active: '/admin/xacml/peps',
               html: WebAnswers.pepCertificate(answer, t) };
    }
    if ((page === '/admin/pki/person' ||
         WebAnswers.one(fields, 'target') === 'person') &&
        answer.privateKeyPem) {
      const fromUser = WebAnswers.one(fields, 'from') === '/admin/users';
      return { title: t.text('consoleAnswers.once.personKey'),
               active: fromUser ? '/admin/users' : '/admin/pki',
               html: WebAnswers.personKey(answer, fields, back, t) };
    }
    return null;
  }

  // A `data:` link for a file the reader saves: markup, so no script.
  /**
   * A `data:` URI of text.
   *
   * @param mime - its type
   * @param text - the text
   * @returns the URI
   */
  static dataUriOf(mime: string, text: string): string {
    const bytes = new TextEncoder().encode(String(text));
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return 'data:' + mime + ';base64,' + btoa(binary);
  }

  /**
   * A button back to where the form was.
   *
   * @param href - where
   * @param label - what it says
   * @returns the HTML
   */
  static backButton(href: string, label: string): string {
    return kit.note('<a class="btn" href="' + kit.esc(href) + '">' +
                    kit.esc(label) + '</a>');
  }

  // THE WORDS OF THESE PAGES ARE TRANSLATED (#539 phase 5): each renderer
  // takes the translator as an optional last parameter, the default when
  // left out. A sentence carrying a link is split around it, the link drawn
  // here; what the server wrote (`message`, `what`, a refusal) is drawn as it
  // came, and a refusal stays English.
  /**
   * A reset password, reset link or app password, shown once, and what
   * else the reset did.
   *
   * @param result - the users action's answer
   * @param back - where the Back button returns to
   * @param t - optional; the translator, the default when left out
   * @returns the HTML
   */
  static credentialReset(result: Json, back: string, t?: Json): string {
    t = t || kit.context().t;
    const who = result.username;
    const out = [];
    if (result.appPassword) {
      // AN APP PASSWORD (#101): shown once, and nothing else happened — no
      // sign-out and no RISC event, so this is the whole answer.
      return '<h2>' + t.html('consoleAnswers.appPassword.heading',
                             { name: result.name, who: who }) + '</h2>' +
        '<div class="secret">' + kit.esc(result.appPassword) + '</div>' +
        kit.warn(t.html('consoleAnswers.appPassword.warn', {
          who: who,
          doors: (result.doorLabels || result.doors || []).join(', ') })) +
        kit.note(t.html('consoleAnswers.appPassword.caep')) +
        kit.note('<a class="btn" href="' + kit.esc(back) + '">' +
                 t.html('consoleAnswers.backTo', { label: who }) + '</a>');
    }
    if (result.password) {
      out.push('<h2>' + t.html('consoleAnswers.reset.passwordHeading',
                               { who: who }) + '</h2>' +
        '<div class="secret">' + kit.esc(result.password) + '</div>' +
        kit.warn(t.html('consoleAnswers.reset.passwordWarn') + (
          result.forcedChange
            ? t.html('consoleAnswers.reset.forced', { who: who })
            : t.html('consoleAnswers.reset.notForced'))));
    }
    if (result.mailError) {
      // A FAILURE, and failures stay English (#539).
      out.push(kit.warn('<strong>The link was NOT mailed:</strong> ' +
        kit.esc(result.mailError) + ' It is shown below instead.'));
    }
    if (result.resetUrl) {
      out.push('<h2>' + t.html('consoleAnswers.reset.linkHeading',
                               { who: who }) +
        '</h2><div class="secret">' + kit.esc(result.resetUrl) + '</div>' +
        kit.warn(t.html('consoleAnswers.reset.linkWarn', {
          who: who,
          until: result.expiresAt || t.text('consoleAnswers.itExpires') }) +
          (result.passwordRevoked
            ? t.html('consoleAnswers.reset.revoked')
            : t.html('consoleAnswers.reset.noPassword'))));
    }
    out.push('<h2>' + t.html('consoleAnswers.reset.elseHeading') + '</h2>' +
      kit.note(kit.esc(result.message || '')) +
      kit.note(t.html('consoleAnswers.reset.signals') + ' <a ' +
      'href="/admin/caep">CAEP</a>' + t.html('consoleAnswers.and') +
      '<a href="/admin/risc">RISC</a>' +
      t.html('consoleAnswers.reset.signalsAfter')));
    out.push(kit.note('<a class="btn" href="' + kit.esc(back) + '">' +
                      t.html('consoleAnswers.backTo', { label: who }) +
                      '</a>'));
    return out.join('');
  }

  /**
   * A person just created: the generated password or activation link
   * shown once, and the entry as it was written.
   *
   * @param result - the create's answer
   * @param env - `base`, for the activation link's absolute form
   * @param t - optional; the translator, the default when left out
   * @returns the HTML
   */
  static createdUser(result: Json, env: Json, t?: Json): string {
    t = t || kit.context().t;
    const base = String((env && env.base) || '');
    const secret = [];
    if (result.password) {
      secret.push('<h2>' + t.html('consoleAnswers.created.passwordHeading') +
        '</h2>' +
        '<div class="secret">' + kit.esc(result.password) + '</div>' +
        kit.warn(t.html('consoleAnswers.created.passwordWarn',
                        { username: result.username })));
    }
    if (result.mailedTo) {
      secret.push('<h2>' + t.html('consoleAnswers.created.mailedHeading') +
        '</h2>' +
        kit.note(t.html('consoleAnswers.created.mailed', {
          to: result.mailedTo,
          until: result.expiresAt || t.text('consoleAnswers.itExpires') }) +
          '<a href="/admin/mail/outbox">' +
          t.html('consoleAnswers.created.mailLink') + '</a>' +
          t.html('consoleAnswers.created.mailedAfter')));
    }
    if (result.mailError) {
      // A FAILURE, and failures stay English (#539).
      secret.push(kit.warn('<strong>The activation link was NOT ' +
        'mailed:</strong> ' + kit.esc(result.mailError) + ' It is shown ' +
        'below instead.'));
    }
    if (result.activationUrl) {
      // ABSOLUTE: a link somebody is about to paste into a message. The
      // operation builds it (`activationLink`) on the address the server
      // would use; this console's own is the fallback.
      secret.push('<h2>' + t.html('consoleAnswers.created.linkHeading') +
        '</h2>' +
        '<div class="secret">' + kit.esc(result.activationLink ||
                                         base + result.activationUrl) +
        '</div>' +
        kit.warn(t.html('consoleAnswers.created.linkWarn', {
          until: result.expiresAt || t.text('consoleAnswers.itExpires') })));
    }
    const attributes = (result.entry && result.entry.attributes) || {};
    return (result.credentialError
        // A FAILURE, and failures stay English (#539).
        ? kit.warn('<strong>The person was created and the credential was ' +
                   'NOT set.</strong> ' + kit.esc(result.credentialError) +
                   ' The name is taken now, by this entry — so set a ' +
                   'credential on it rather than creating them again.')
        : '<div class="ok">' +
          t.html('consoleAnswers.created.exists', { dn: result.dn }) +
          '</div>') +
      secret.join('') +
      '<h2>' + t.html('consoleAnswers.created.writtenHeading') + '</h2>' +
      kit.note(kit.esc(result.message)) +
      '<table><tr><th>' + t.html('consoleAnswers.attribute') + '</th><th>' +
      t.html('consoleAnswers.value') + '</th></tr>' +
      Object.keys(attributes).sort().map(function (name) {
        // THE TWO VERIFIERS ARE NAMED AND NOT PRINTED: a scrypt hash is not
        // the value, but it is what a sign-in is checked against, and this
        // page's subject is what an operator just typed.
        if (name === 'userpassword' || name === 'stsactivationtoken') {
          return '<tr><td><code>' + kit.esc(name) + '</code></td><td ' +
            'class="state-none">' + t.html('consoleAnswers.created.hashSet') +
            '</td></tr>';
        }
        return '<tr><td><code>' + kit.esc(name) + '</code></td><td>' +
          kit.esc([].concat(attributes[name] || []).join(', ')) +
          '</td></tr>';
      }).join('') +
      '</table>' +
      kit.note(t.html('consoleAnswers.created.entry') +
      '<a href="/admin/ldap/directory">' +
      t.html('consoleAnswers.created.directoryPage') + '</a>' +
      t.html('consoleAnswers.created.entryAfter')) +
      '<div class="formrow"><a href="' + kit.esc('/admin/users' +
        kit.queryWith({ user: result.username }, {})) +
      '">' + t.html('consoleAnswers.created.theirRow') + '</a></div>' +
      kit.note('<a href="/admin/users/new">' +
      t.html('consoleAnswers.created.another') + '</a> &middot; <a ' +
      'href="/admin/ldap/directory">' +
      t.html('consoleAnswers.created.everyEntry') + '</a> ' +
      '&middot; <a href="/admin/users">' +
      t.html('consoleAnswers.created.backToUsers') + '</a>' +
      t.html('consoleAnswers.created.remember'));
  }

  /**
   * A new realm's bootstrap administrator's password, shown once.
   *
   * @param result - the realm create's answer
   * @param env - `realmRoot`, the service's own root
   * @param t - optional; the translator, the default when left out
   * @returns the HTML
   */
  static realmCreated(result: Json, env: Json, t?: Json): string {
    t = t || kit.context().t;
    const back = '/admin/realms' + kit.queryWith({ realm: result.realm }, {});
    const realmUrl = String((env && env.realmRoot) || '') +
                     String(result.prefix || '') + '/admin';
    return '<h2>' + t.html('consoleAnswers.realm.heading',
                           { realm: result.realm }) +
      '</h2><table class="key"><tr>' +
      '<th>' + t.html('consoleAnswers.username') + '</th><td><code>' +
      kit.esc(result.username) + '</code></td></tr></table>' +
      '<div class="secret">' + kit.esc(result.password) + '</div>' +
      kit.warn(t.html('consoleAnswers.realm.warn', { realm: result.realm })) +
      kit.note('<a class="btn" href="' + kit.esc(back) + '">' +
               t.html('consoleAnswers.realm.back') + '</a> &middot; <a ' +
               'href="' + kit.esc(realmUrl) + '">' +
               t.html('consoleAnswers.realm.console') + '</a>');
  }

  /**
   * A keytab, made or rotated, shown once with what it holds.
   *
   * @param result - the Kerberos principals action's answer
   * @param t - optional; the translator, the default when left out
   * @returns the HTML
   */
  static keytab(result: Json, t?: Json): string {
    t = t || kit.context().t;
    // A PERSON'S KEYTAB (#59) is made again from a password, and this one
    // came from a password the administrator just set — which the page says
    // above everything else.
    const person = !!result.username;
    return kit.warn(t.html('consoleAnswers.keytab.once') +
        (person
          ? t.html('consoleAnswers.keytab.oncePerson')
          : t.html('consoleAnswers.keytab.onceService'))) +
      (person
        ? kit.warn(t.html('consoleAnswers.keytab.changed', {
            username: result.username,
            how: result.generated ? 'generated' : 'typed' }))
        : '') +
      kit.note(kit.esc(result.message)) +
      '<table class="key"><tr><th>' + t.html('consoleAnswers.principal') +
      '</th><td><code>' +
      kit.esc(result.principal) + '</code></td></tr><tr><th>kvno</th><td>' +
      kit.esc(String(result.kvno)) + '</td></tr>' +
      ((result.keytabKvnos || []).length > 1
        ? '<tr><th>' + t.html('consoleAnswers.keytab.versions') +
          '</th><td>' +
          t.html('consoleAnswers.keytab.versionsText',
                 { kvnos: result.keytabKvnos.join(', ') }) + '</td></tr>'
        : '') +
      '<tr><th>' + t.html('consoleAnswers.keytab.enctypes') + '</th><td>' +
      (result.etypes || []).map(function (e) {
        return '<code>' + kit.esc(String(e)) + '</code>';
      }).join(' ') + '</td></tr></table>' +
      '<p><a class="btn" download="' + kit.esc(result.keytabFilename) +
      '" href="data:application/octet-stream;base64,' +
      kit.esc(result.keytab) + '">' +
      t.html('consoleAnswers.keytab.save', { file: result.keytabFilename }) +
      '</a></p>' +
      kit.note(t.html('consoleAnswers.keytab.terminal',
                      { file: result.keytabFilename })) +
      '<textarea readonly rows="6" name="keytab-base64">' +
      kit.esc(result.keytab) + '</textarea>' +
      kit.note(person
        ? '<a href="' + kit.esc('/admin/users' +
            kit.queryWith({ user: result.username }, {})) + '">' +
          t.html('consoleAnswers.backTo', { label: result.username }) + '</a>'
        : '<a href="/admin/kerberos/principals">' +
          t.html('consoleAnswers.keytab.backToPrincipals') + '</a>');
  }

  /**
   * An ACME External Account Binding key and its certbot line, once.
   *
   * @param result - `create-eab`'s answer
   * @param back - the page the form was on
   * @param t - optional; the translator, the default when left out
   * @returns the HTML
   */
  static eabKey(result: Json, back: string, t?: Json): string {
    t = t || kit.context().t;
    const code = function (value) {
      return '<code>' + kit.esc(value) + '</code>';
    };
    return kit.warn(t.html('consoleAnswers.eab.warn')) +
      '<table class="kv"><tr><th>' + t.html('consoleAnswers.eab.for') +
      '</th><td>' + code(result.targetUri) +
      '</td></tr><tr><th>' + t.html('consoleAnswers.eab.directory') +
      '</th><td>' + code(result.directory) +
      '</td></tr><tr><th>' + t.html('consoleAnswers.eab.kid') + '</th><td>' +
      code(result.kid) +
      '</td></tr><tr><th>' + t.html('consoleAnswers.eab.hmac') + '</th><td>' +
      code(result.hmacKey) + '</td></tr><tr><th>MAC</th><td>' +
      code(result.alg) + '</td></tr><tr><th>' +
      t.html('consoleAnswers.eab.unusedUntil') + '</th><td>' +
      kit.esc(result.expiresAt) + '</td></tr></table>' +
      '<h2>certbot</h2><pre>' + kit.esc(result.certbot) + '</pre>' +
      '<p class="links"><a href="' + kit.esc(back) + '">' +
      t.html('consoleAnswers.back') + '</a> · ' +
      '<a href="/admin/acme#eab">' + t.html('consoleAnswers.eab.backToAcme') +
      '</a></p>';
  }

  /**
   * A SCEP challenge password, once.
   *
   * @param result - the challenge's answer
   * @param back - the page the form was on
   * @param t - optional; the translator, the default when left out
   * @returns the HTML
   */
  static scepChallenge(result: Json, back: string, t?: Json): string {
    t = t || kit.context().t;
    const code = function (value) {
      return '<code>' + kit.esc(value) + '</code>';
    };
    return kit.warn(t.html('consoleAnswers.scep.warn', {
        uri: result.entryUri, profile: result.profile })) +
      '<table class="kv"><tr><th>' + t.html('consoleAnswers.scep.challenge') +
      '</th><td>' +
      code(result.challenge) + '</td></tr><tr><th>' +
      t.html('consoleAnswers.scep.expires') + '</th><td>' +
      kit.esc(result.expiresAt) + '</td></tr><tr><th>' +
      t.html('consoleAnswers.scep.url') + '</th><td>' +
      code(result.url) + '</td></tr><tr><th>' +
      t.html('consoleAnswers.scep.plainUrl') + '</th><td>' +
      code(result.plainUrl) + '</td></tr></table><h3>' +
      t.html('consoleAnswers.scep.withSscep') + '</h3><pre>' +
      kit.esc(result.hint) + '</pre>' +
      '<p class="links"><a href="' + kit.esc(back) + '">' +
      t.html('consoleAnswers.back') + '</a></p>';
  }

  /**
   * A generated DID key pair's private half, once.
   *
   * @param answer - `generate-did-key`'s answer
   * @param fields - the form's fields
   * @param back - the page the form was on
   * @param t - optional; the translator, the default when left out
   * @returns the HTML
   */
  static didKey(answer: Json, fields: Json, back: string, t?: Json): string {
    t = t || kit.context().t;
    const identifier = String((answer.application &&
                               answer.application.identifier) ||
                              WebAnswers.one(fields, 'application'));
    const jwk = JSON.stringify(answer.privateJwk, null, 2);
    const file = String(answer.kid || 'did-key').slice(0, 16);
    return kit.warn('<p>' + t.html('consoleAnswers.did.warn') +
      '</p><p><a class="btn" download="' +
      kit.esc(file) + '.jwk.json" href="' +
      kit.esc(WebAnswers.dataUriOf('application/json', jwk)) +
      '">' + t.html('consoleAnswers.did.downloadJwk') +
      '</a> <a class="btn" download="' + kit.esc(file) +
      '.pem" href="' + kit.esc(WebAnswers.dataUriOf(
        'application/x-pem-file', answer.privateKeyPem)) +
      '">' + t.html('consoleAnswers.did.downloadPem') + '</a></p>',
      t.text('consoleAnswers.privateKeyOnce')) +
      '<table><tr><th>DID</th><td><code>' + kit.esc(answer.did) +
      '</code></td></tr><tr><th>' + t.html('consoleAnswers.did.method') +
      '</th><td><code>' +
      kit.esc(answer.verificationMethod) + '</code></td></tr>' +
      '<tr><th>' + t.html('consoleAnswers.algorithm') + '</th><td>' +
      kit.esc(answer.algorithm) +
      '</td></tr><tr><th>' + t.html('consoleAnswers.did.document') +
      '</th><td><a href="' +
      kit.esc(answer.documentUrl) + '"><code>' +
      kit.esc(answer.documentUrl) + '</code></a></td></tr></table>' +
      '<h3>' + t.html('consoleAnswers.did.jwkHeading') +
      '</h3><textarea readonly rows="9" cols="80">' +
      kit.esc(jwk) + '</textarea>' +
      '<h3>' + t.html('consoleAnswers.did.pemHeading') +
      '</h3><textarea readonly rows="6" ' +
      'cols="80">' + kit.esc(answer.privateKeyPem) + '</textarea>' +
      kit.note(t.html('consoleAnswers.did.how')) +
      WebAnswers.backButton(back, t.text('consoleAnswers.backTo',
                                         { label: identifier }));
  }

  /**
   * An issued RFC 8705 client certificate's three files, once.
   *
   * @param answer - `issue-tls-client-certificate`'s answer
   * @param fields - the form's fields
   * @param back - the page the form was on
   * @param t - optional; the translator, the default when left out
   * @returns the HTML
   */
  static tlsClientCertificate(answer: Json, fields: Json,
                              back: string, t?: Json): string {
    t = t || kit.context().t;
    const files = answer.files;
    const cert = answer.certificate || {};
    const identifier = String((answer.application &&
                               answer.application.identifier) ||
                              WebAnswers.one(fields, 'application'));
    const link = function (file, href) {
      return '<a class="btn" download="' + kit.esc(file.name) + '" href="' +
        kit.esc(href) + '">' +
        t.html('consoleAnswers.tls.download', { file: file.name }) + '</a>';
    };
    return kit.warn('<p>' + t.html('consoleAnswers.tls.warn') + '</p><p>' +
      link(files.pkcs12, 'data:' + files.pkcs12.mime + ';base64,' +
                         files.pkcs12.base64) + ' ' +
      link(files.key, WebAnswers.dataUriOf(files.key.mime, files.key.text)) +
      ' ' +
      link(files.chain, WebAnswers.dataUriOf(files.chain.mime,
                                             files.chain.text)) +
      '</p>', t.text('consoleAnswers.privateKeyOnce')) +
      '<table><tr><th>' + t.html('consoleAnswers.tls.issuedTo') +
      '</th><td><code>' + kit.esc(cert.subject) +
      '</code><div class="sub">subjectAltName <code>' +
      kit.esc(cert.implicitName) + '</code></div></td></tr>' +
      '<tr><th>' + t.html('consoleAnswers.serial') + '</th><td><code>' +
      kit.esc(cert.serialHex) +
      '</code></td></tr><tr><th>' + t.html('consoleAnswers.tls.thumbprint') +
      '</th><td><code>' +
      kit.esc(cert.thumbprint) + '</code></td></tr><tr><th>' +
      t.html('consoleAnswers.tls.key') + '</th><td>' +
      kit.esc(cert.keyAlg) + '</td></tr><tr><th>' +
      t.html('consoleAnswers.tls.goodUntil') + '</th><td><code>' +
      kit.esc(cert.notAfter) + '</code></td></tr></table>' +
      kit.note(t.html('consoleAnswers.tls.how', {
        client: identifier, chain: files.chain.name,
        key: files.key.name })) +
      WebAnswers.backButton(back, t.text('consoleAnswers.backTo',
                                         { label: identifier }));
  }

  /**
   * A remote PEP's listener certificate and its private key, once.
   *
   * @param result - `issue-pep-certificate`'s answer
   * @param t - optional; the translator, the default when left out
   * @returns the HTML
   */
  static pepCertificate(result: Json, t?: Json): string {
    t = t || kit.context().t;
    return kit.note('<p>' + kit.esc(result.what) + '</p>') +
      '<table><tr><th>PEP</th><td><code>' + kit.esc(result.pep) +
      '</code></td></tr><tr><th>' + t.html('consoleAnswers.realm') +
      '</th><td><code>' +
      kit.esc(result.realm) + '</code></td></tr><tr><th>' +
      t.html('consoleAnswers.serial') + '</th><td>' +
      '<code>' + kit.esc(result.serialHex) + '</code></td></tr>' +
      '<tr><th>' + t.html('consoleAnswers.pep.names') + '</th><td>' +
      kit.esc([].concat(result.dnsNames || [],
        result.ipAddresses || []).join(', ')) + '</td></tr>' +
      '<tr><th>' + t.html('consoleAnswers.validUntil') + '</th><td>' +
      kit.esc(result.notAfter) +
      '</td></tr></table>' +
      kit.warn('<p>' + t.html('consoleAnswers.pep.warn') + '</p><pre>' +
        kit.esc(result.privateKeyPem) + '</pre>',
        t.text('consoleAnswers.privateKeyOnce')) +
      '<p>' + t.html('consoleAnswers.pep.chain') + '</p><pre>' +
      kit.esc(result.fullChainPem) + '</pre>' +
      '<p>' + t.html('consoleAnswers.pep.anchor') + '</p><pre>' +
      kit.esc(result.anchorPem) + '</pre>' +
      WebAnswers.backButton('/admin/xacml/peps',
                            t.text('consoleAnswers.pep.back'));
  }

  /**
   * A person's assertion signing key pair (RFC 7523 or RFC 7522), once.
   *
   * @param result - the PKI issue's answer, `target=person`
   * @param fields - the form's fields
   * @param back - the page the form was on
   * @param t - optional; the translator, the default when left out
   * @returns the HTML
   */
  static personKey(result: Json, fields: Json, back: string,
                   t?: Json): string {
    t = t || kit.context().t;
    const saml = result.purpose === 'saml';
    const message = String(result.why || result.message ||
                           t.text('consoleAnswers.done'));
    return kit.note(kit.esc(message).replace(/\*\*(.+?)\*\*/g,
                                             '<strong>$1</strong>')) +
      kit.warn('<p>' + t.html('consoleAnswers.person.warn', {
          person: String(result.person),
          attribute: saml ? 'stsSamlAssertionPrivateKey'
                          : 'stsAssertionPrivateKey' }) + '</p>' +
        (saml
          // THE RFC 7522 SHAPE: what the person signs is an <Assertion>.
          ? '<p>' + t.html('consoleAnswers.person.saml', {
              issuer: String(result.issuer),
              thumbprint: String(result.thumbprint) }) + '</p>'
          : '<p>' + t.html('consoleAnswers.person.jwt', {
              issuer: String(result.issuer), kid: String(result.kid),
              alg: String(result.jwsAlg) }) + '</p>') +
        '<pre>' + kit.esc(String(result.privateKeyPem)) + '</pre>' +
        '<p>' + t.html('consoleAnswers.person.certificate') + '</p>' +
        '<pre>' + kit.esc(String(result.certificatePem)) + '</pre>',
        t.text('consoleAnswers.privateKeyOnce')) +
      WebAnswers.backButton(back, WebAnswers.one(fields, 'identifier')
        ? t.text('consoleAnswers.backTo', {
            label: WebAnswers.one(fields, 'identifier').trim() })
        : t.text('consoleAnswers.back'));
  }
}

export = WebAnswers;
