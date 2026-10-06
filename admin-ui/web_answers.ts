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
   * @returns `{ json, banner }` to draw in place, or null
   */
  static redraw(page: string, action: string, fields: Json, answer: Json,
                json: Json): Json {
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
      return WebAnswers.newApplicationRedraw(action, fields, answer, json);
    }
    if (page === '/admin/pki/certificate' && answer && answer.workbench) {
      // THE WORKBENCH'S NEXT DRAFT, refused or not: a refusal that drew the
      // form empty would be worse than the refusal.
      const out = WebAnswers.copy(json);
      out.workbench = answer.workbench;
      const message = ok ? String(answer.why || answer.message || 'Done.')
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
   * @returns `{ json, banner }`, or null
   */
  static newApplicationRedraw(action: string, fields: Json, answer: Json,
                              json: Json): Json {
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
                    notice: 'A client secret was generated and is in the ' +
                      'oauthClientSecret box below. Nothing has been ' +
                      'written: it becomes this application\'s credential ' +
                      'when you create it. Its token endpoint authentication ' +
                      'method is set to client_secret_basic where none was ' +
                      'chosen, and the token endpoint accepts the secret ' +
                      'either in an Authorization: Basic header ' +
                      '(client_secret_basic) or as a client_secret form ' +
                      'parameter (client_secret_post).' };
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
   * @returns `{ json, banner }`
   */
  static filled(fields: Json, answer: Json, json: Json): Json {
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
             banner: '<div class="ok"><strong>Filled in with the invented ' +
               'person for ' + kit.esc(username) + '.</strong> Nobody has ' +
               'been created. Edit or clear anything you like and press ' +
               'Create the user.</div>' };
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
   * @returns `{ title, active, html }`, or null
   */
  static once(page: string, action: string, fields: Json, answer: Json,
              env: Json): Json {
    if (!answer || !answer.ok) {
      return null;
    }
    const back = String((env && env.back) || '/admin');
    if (page === '/admin/users/new' && action === 'create') {
      return { title: 'User created', active: '/admin/users',
               html: WebAnswers.createdUser(answer, env) };
    }
    if (answer.keytab) {
      return { title: 'Kerberos keytab',
               active: answer.username ? '/admin/users'
                                       : '/admin/kerberos/principals',
               html: WebAnswers.keytab(answer) };
    }
    if (page === '/admin/users' &&
        (answer.password || answer.resetUrl || answer.appPassword)) {
      return { title: 'Credential reset', active: '/admin/users',
               html: WebAnswers.credentialReset(answer, back) };
    }
    if (page === '/admin/realms' && answer.password) {
      return { title: 'Realm created', active: '/admin/realms',
               html: WebAnswers.realmCreated(answer, env) };
    }
    if (answer.hmacKey) {
      return { title: 'ACME — EAB key', active: '/admin/acme',
               html: WebAnswers.eabKey(answer, back) };
    }
    if (answer.challenge && page === '/admin/scep') {
      return { title: 'SCEP', active: '/admin/scep',
               html: WebAnswers.scepChallenge(answer, back) };
    }
    if (page === '/admin/applications' && action === 'generate-did-key' &&
        answer.privateJwk) {
      return { title: 'DID key pair', active: '/admin/applications',
               html: WebAnswers.didKey(answer, fields, back) };
    }
    if (page === '/admin/applications' &&
        action === 'issue-tls-client-certificate' && answer.files) {
      return { title: 'TLS client certificate', active: '/admin/applications',
               html: WebAnswers.tlsClientCertificate(answer, fields, back) };
    }
    if (page === '/admin/xacml/peps' &&
        action === 'issue-pep-certificate' && answer.privateKeyPem) {
      return { title: 'Listener certificate', active: '/admin/xacml/peps',
               html: WebAnswers.pepCertificate(answer) };
    }
    if ((page === '/admin/pki/person' ||
         WebAnswers.one(fields, 'target') === 'person') &&
        answer.privateKeyPem) {
      const fromUser = WebAnswers.one(fields, 'from') === '/admin/users';
      return { title: 'Signing key pair',
               active: fromUser ? '/admin/users' : '/admin/pki',
               html: WebAnswers.personKey(answer, fields, back) };
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

  /**
   * A reset password, reset link or app password, shown once, and what
   * else the reset did.
   *
   * @param result - the users action's answer
   * @param back - where the Back button returns to
   * @returns the HTML
   */
  static credentialReset(result: Json, back: string): string {
    const who = kit.esc(result.username);
    const out = [];
    if (result.appPassword) {
      // AN APP PASSWORD (#101): shown once, and nothing else happened — no
      // sign-out and no RISC event, so this is the whole answer.
      return '<h2>The app password "' + kit.esc(result.name) + '" for ' +
        who + ', shown once</h2>' +
        '<div class="secret">' + kit.esc(result.appPassword) + '</div>' +
        kit.warn('<strong>Note it now.</strong> This service stores a ' +
        'scrypt hash and cannot show it again. Give it to ' + who + ' by a ' +
        'channel you trust. It is accepted at ' +
        kit.esc((result.doorLabels || result.doors || []).join(', ')) +
        ' only — never at the sign-in screen.') +
        kit.note('A CAEP <code>credential-change</code> (<code>password' +
        '</code>, <code>create</code>) went to every stream that asked for ' +
        'it and covers this person.') +
        kit.note('<a class="btn" href="' + kit.esc(back) + '">Back to ' +
                 who + '</a>');
    }
    if (result.password) {
      out.push('<h2>The new password for ' + who + ', shown once</h2>' +
        '<div class="secret">' + kit.esc(result.password) + '</div>' +
        kit.warn('<strong>Note it now.</strong> This service stores a ' +
        'scrypt hash and cannot show it again — not this console, not ' +
        '<code>/admin-api</code>. ' + (result.forcedChange
          ? 'It works ONCE, at the sign-in screen, where ' + who + ' is ' +
            'made to choose their own before anything is signed in.'
          : 'The forced change could not be recorded, so it will go on ' +
            'working until somebody changes it.')));
    }
    if (result.mailError) {
      out.push(kit.warn('<strong>The link was NOT mailed:</strong> ' +
        kit.esc(result.mailError) + ' It is shown below instead.'));
    }
    if (result.resetUrl) {
      out.push('<h2>The password reset link for ' + who + ', shown once' +
        '</h2><div class="secret">' + kit.esc(result.resetUrl) + '</div>' +
        kit.warn('<strong>Send it to ' + who + ' by a channel you trust. ' +
        'Valid until ' + kit.esc(result.expiresAt || 'it expires') +
        '.</strong> Anybody holding it can set this person\'s password, so ' +
        'treat it as the credential it is. It is spent when the new ' +
        'password is stored, not when it is opened. ' +
        (result.passwordRevoked
          ? 'Their old password was REMOVED, so until the link is used ' +
            'they cannot sign in with a password.'
          : 'They had no password to remove.')));
    }
    out.push('<h2>What else happened</h2>' +
      kit.note(kit.esc(result.message || '')) +
      kit.note('<strong>Shared Signals</strong>: a CAEP credential-change ' +
      'and a RISC account-credential-change-required went to every stream ' +
      'that asked for those types and covers this person, and each session ' +
      'the sign-out ended sent its own CAEP session-revoked. <a ' +
      'href="/admin/caep">CAEP</a> and <a href="/admin/risc">RISC</a> show ' +
      'what was delivered.'));
    out.push(kit.note('<a class="btn" href="' + kit.esc(back) + '">Back to ' +
                      who + '</a>'));
    return out.join('');
  }

  /**
   * A person just created: the generated password or activation link
   * shown once, and the entry as it was written.
   *
   * @param result - the create's answer
   * @param env - `base`, for the activation link's absolute form
   * @returns the HTML
   */
  static createdUser(result: Json, env: Json): string {
    const base = String((env && env.base) || '');
    const secret = [];
    if (result.password) {
      secret.push('<h2>The generated password, shown once</h2>' +
        '<div class="secret">' + kit.esc(result.password) + '</div>' +
        kit.warn('<strong>This is the only time this value exists ' +
        'anywhere but in the hash on the entry.</strong> Copy it now and ' +
        'send it to ' + kit.esc(result.username) + ' by whatever channel ' +
        'you already use. Nothing in this service can show it again — not ' +
        'this console, not <code>/admin-api</code>, not an ' +
        '<code>ldapsearch</code>, which sees a scrypt hash. If it is lost, ' +
        'set a new one; there is no recovery because there is nothing to ' +
        'recover.'));
    }
    if (result.mailedTo) {
      secret.push('<h2>The activation link was mailed</h2>' +
        kit.note('It went to <strong>' + kit.esc(result.mailedTo) +
                 '</strong>, valid until ' +
                 kit.esc(result.expiresAt || 'it expires') + ', and is ' +
                 'not shown here. Monitoring &rarr; ' +
                 '<a href="/admin/mail/outbox">Mail</a> shows where it got ' +
                 'to.'));
    }
    if (result.mailError) {
      secret.push(kit.warn('<strong>The activation link was NOT ' +
        'mailed:</strong> ' + kit.esc(result.mailError) + ' It is shown ' +
        'below instead.'));
    }
    if (result.activationUrl) {
      // ABSOLUTE: a link somebody is about to paste into a message. The
      // operation builds it (`activationLink`) on the address the server
      // would use; this console's own is the fallback.
      secret.push('<h2>The activation link, shown once</h2>' +
        '<div class="secret">' + kit.esc(result.activationLink ||
                                         base + result.activationUrl) +
        '</div>' +
        kit.warn('<strong>Valid until ' +
        kit.esc(result.expiresAt || 'it expires') + ', and shown once.' +
        '</strong> This service stores only a hash of the token in it and ' +
        'cannot produce the link again — issuing another invalidates this ' +
        'one, which is also how a link that never arrived is replaced. ' +
        '<strong>Treat it as the credential it is</strong>: anybody holding ' +
        'it can finish setting up this account, choosing a password or ' +
        'enrolling a security key. It is spent when that setup FINISHES ' +
        'rather than when the link is opened, so a mail scanner or a ' +
        'browser prefetch cannot burn it. There is deliberately no ' +
        'self-service version of this link: until the account is activated ' +
        'nobody has proved the address on it is theirs. Tick <em>mail the ' +
        'activation link</em> on the form to have this service send it ' +
        'instead.'));
    }
    const attributes = (result.entry && result.entry.attributes) || {};
    return (result.credentialError
        ? kit.warn('<strong>The person was created and the credential was ' +
                   'NOT set.</strong> ' + kit.esc(result.credentialError) +
                   ' The name is taken now, by this entry — so set a ' +
                   'credential on it rather than creating them again.')
        : '<div class="ok"><strong>' + kit.esc(result.dn) + '</strong> now ' +
          'exists.</div>') +
      secret.join('') +
      '<h2>What was written</h2>' +
      kit.note(kit.esc(result.message)) +
      '<table><tr><th>Attribute</th><th>Value</th></tr>' +
      Object.keys(attributes).sort().map(function (name) {
        // THE TWO VERIFIERS ARE NAMED AND NOT PRINTED: a scrypt hash is not
        // the value, but it is what a sign-in is checked against, and this
        // page's subject is what an operator just typed.
        if (name === 'userpassword' || name === 'stsactivationtoken') {
          return '<tr><td><code>' + kit.esc(name) + '</code></td><td ' +
            'class="state-none">set — a scrypt hash, not shown here</td>' +
            '</tr>';
        }
        return '<tr><td><code>' + kit.esc(name) + '</code></td><td>' +
          kit.esc([].concat(attributes[name] || []).join(', ')) +
          '</td></tr>';
      }).join('') +
      '</table>' +
      kit.note('The entry exactly as the store holds it, which is what an ' +
      '<code>ldapsearch</code> under this realm\'s base DN returns. ' +
      'Attribute names are lower-cased because LDAP attribute descriptions ' +
      'are case-insensitive and this store normalises them on the way in. ' +
      '<strong>The two attributes that hold a verifier are named rather ' +
      'than printed</strong>; <a href="/admin/ldap/directory">the directory ' +
      'page</a> shows both.') +
      '<div class="formrow"><a href="' + kit.esc('/admin/users' +
        kit.queryWith({ user: result.username }, {})) +
      '">Their row on Users &rsaquo;</a></div>' +
      kit.note('<a href="/admin/users/new">Create another</a> &middot; <a ' +
      'href="/admin/ldap/directory">Every entry in the directory</a> ' +
      '&middot; <a href="/admin/users">Back to Users</a>. Remember that ' +
      'they will not appear in the Users TABLE until they authenticate: ' +
      'that list is who this service has SEEN.');
  }

  /**
   * A new realm's bootstrap administrator's password, shown once.
   *
   * @param result - the realm create's answer
   * @param env - `realmRoot`, the service's own root
   * @returns the HTML
   */
  static realmCreated(result: Json, env: Json): string {
    const back = '/admin/realms' + kit.queryWith({ realm: result.realm }, {});
    const realmUrl = String((env && env.realmRoot) || '') +
                     String(result.prefix || '') + '/admin';
    return '<h2>The "' + kit.esc(result.realm) + '" realm\'s ' +
      'administrator, shown once</h2><table class="key"><tr>' +
      '<th>Username</th><td><code>' + kit.esc(result.username) +
      '</code></td></tr></table>' +
      '<div class="secret">' + kit.esc(result.password) + '</div>' +
      kit.warn('<strong>Note it now.</strong> It is stored as a scrypt ' +
      'hash and cannot be shown again. It works once, at that realm\'s ' +
      'sign-in screen, where a new password must be chosen. This account ' +
      'administers the "' + kit.esc(result.realm) + '" realm and nothing ' +
      'else.') +
      kit.note('<a class="btn" href="' + kit.esc(back) + '">Back to the ' +
               'realm</a> &middot; <a href="' + kit.esc(realmUrl) +
               '">its console</a>');
  }

  /**
   * A keytab, made or rotated, shown once with what it holds.
   *
   * @param result - the Kerberos principals action's answer
   * @returns the HTML
   */
  static keytab(result: Json): string {
    // A PERSON'S KEYTAB (#59) is made again from a password, and this one
    // came from a password the administrator just set — which the page says
    // above everything else.
    const person = !!result.username;
    return kit.warn('<strong>This keytab is shown once.</strong> It is not ' +
        'kept in the clear anywhere and this service cannot show it again; ' +
        (person
          ? 'another is made by resetting the password again, or by the ' +
            'person from their own password on the portal.'
          : 'a lost keytab is replaced by rotating, which makes a new key.')) +
      (person
        ? kit.warn('<strong>' + kit.esc(result.username) + '\'s password ' +
            'was changed</strong> to ' +
            (result.generated
              ? 'a generated one that nobody was shown, so this keytab is ' +
                'the only thing that signs them in until a password is set ' +
                'again'
              : 'the one you typed') +
            ', and they were signed out of everything.')
        : '') +
      kit.note(kit.esc(result.message)) +
      '<table class="key"><tr><th>Principal</th><td><code>' +
      kit.esc(result.principal) + '</code></td></tr><tr><th>kvno</th><td>' +
      kit.esc(String(result.kvno)) + '</td></tr>' +
      ((result.keytabKvnos || []).length > 1
        ? '<tr><th>Versions in the keytab</th><td>' +
          kit.esc(result.keytabKvnos.join(', ')) + ' — the previous ' +
          'version stays in it, as after <code>ktadd</code>, for tickets ' +
          'already issued under it</td></tr>'
        : '') +
      '<tr><th>Enctypes</th><td>' + (result.etypes || []).map(function (e) {
        return '<code>' + kit.esc(String(e)) + '</code>';
      }).join(' ') + '</td></tr></table>' +
      '<p><a class="btn" download="' + kit.esc(result.keytabFilename) +
      '" href="data:application/octet-stream;base64,' +
      kit.esc(result.keytab) + '">Save ' + kit.esc(result.keytabFilename) +
      '</a></p>' +
      kit.note('Or, in a terminal: <code>base64 -d &gt; ' +
               kit.esc(result.keytabFilename) + '</code> and paste the text ' +
               'below, then <code>klist -k -e ' +
               kit.esc(result.keytabFilename) + '</code> to see the ' +
               'entries.') +
      '<textarea readonly rows="6" name="keytab-base64">' +
      kit.esc(result.keytab) + '</textarea>' +
      kit.note(person
        ? '<a href="' + kit.esc('/admin/users' +
            kit.queryWith({ user: result.username }, {})) + '">Back to ' +
          kit.esc(result.username) + '</a>'
        : '<a href="/admin/kerberos/principals">Back to the Kerberos ' +
          'principals</a>');
  }

  /**
   * An ACME External Account Binding key and its certbot line, once.
   *
   * @param result - `create-eab`'s answer
   * @param back - the page the form was on
   * @returns the HTML
   */
  static eabKey(result: Json, back: string): string {
    const code = function (value) {
      return '<code>' + kit.esc(value) + '</code>';
    };
    return kit.warn('<strong>Copy the HMAC key now.</strong> It is stored ' +
        'sealed on the entry and is never shown again.') +
      '<table class="kv"><tr><th>For</th><td>' + code(result.targetUri) +
      '</td></tr><tr><th>Directory</th><td>' + code(result.directory) +
      '</td></tr><tr><th>Key id (--eab-kid)</th><td>' + code(result.kid) +
      '</td></tr><tr><th>HMAC key (--eab-hmac-key)</th><td>' +
      code(result.hmacKey) + '</td></tr><tr><th>MAC</th><td>' +
      code(result.alg) + '</td></tr><tr><th>Unused until</th><td>' +
      kit.esc(result.expiresAt) + '</td></tr></table>' +
      '<h2>certbot</h2><pre>' + kit.esc(result.certbot) + '</pre>' +
      '<p class="links"><a href="' + kit.esc(back) + '">Back</a> · ' +
      '<a href="/admin/acme#eab">Back to ACME</a></p>';
  }

  /**
   * A SCEP challenge password, once.
   *
   * @param result - the challenge's answer
   * @param back - the page the form was on
   * @returns the HTML
   */
  static scepChallenge(result: Json, back: string): string {
    const code = function (value) {
      return '<code>' + kit.esc(value) + '</code>';
    };
    return kit.warn('<strong>The challenge password for ' +
        kit.esc(result.entryUri) + ' (' + kit.esc(result.profile) + '). It ' +
        'is shown once and cannot be shown again.</strong>') +
      '<table class="kv"><tr><th>Challenge</th><td>' +
      code(result.challenge) + '</td></tr><tr><th>Expires</th><td>' +
      kit.esc(result.expiresAt) + '</td></tr><tr><th>SCEP URL</th><td>' +
      code(result.url) + '</td></tr><tr><th>Plain-HTTP SCEP URL</th><td>' +
      code(result.plainUrl) + '</td></tr></table><h3>With sscep</h3><pre>' +
      kit.esc(result.hint) + '</pre>' +
      '<p class="links"><a href="' + kit.esc(back) + '">Back</a></p>';
  }

  /**
   * A generated DID key pair's private half, once.
   *
   * @param answer - `generate-did-key`'s answer
   * @param fields - the form's fields
   * @param back - the page the form was on
   * @returns the HTML
   */
  static didKey(answer: Json, fields: Json, back: string): string {
    const identifier = String((answer.application &&
                               answer.application.identifier) ||
                              WebAnswers.one(fields, 'application'));
    const jwk = JSON.stringify(answer.privateJwk, null, 2);
    const file = String(answer.kid || 'did-key').slice(0, 16);
    return kit.warn('<p><strong>This is the only time the private key is ' +
      'shown.</strong> This service keeps it sealed, to sign the ' +
      'application&rsquo;s Domain Linkage Credentials, and shows it on no ' +
      'page after this one. If your copy is lost, generate another with ' +
      '<em>replace</em> ticked.</p><p><a class="btn" download="' +
      kit.esc(file) + '.jwk.json" href="' +
      kit.esc(WebAnswers.dataUriOf('application/json', jwk)) +
      '">Download the JWK</a> <a class="btn" download="' + kit.esc(file) +
      '.pem" href="' + kit.esc(WebAnswers.dataUriOf(
        'application/x-pem-file', answer.privateKeyPem)) +
      '">Download the PEM</a></p>', 'The private key, once') +
      '<table><tr><th>DID</th><td><code>' + kit.esc(answer.did) +
      '</code></td></tr><tr><th>Verification method</th><td><code>' +
      kit.esc(answer.verificationMethod) + '</code></td></tr>' +
      '<tr><th>Algorithm</th><td>' + kit.esc(answer.algorithm) +
      '</td></tr><tr><th>Document</th><td><a href="' +
      kit.esc(answer.documentUrl) + '"><code>' +
      kit.esc(answer.documentUrl) + '</code></a></td></tr></table>' +
      '<h3>Private key (JWK)</h3><textarea readonly rows="9" cols="80">' +
      kit.esc(jwk) + '</textarea>' +
      '<h3>Private key (PKCS#8 PEM)</h3><textarea readonly rows="6" ' +
      'cols="80">' + kit.esc(answer.privateKeyPem) + '</textarea>' +
      kit.note('Sign as the DID with this key and name the verification ' +
      'method above as the <code>kid</code>; a verifier resolves the DID ' +
      'and finds the public key in the document.') +
      WebAnswers.backButton(back, 'Back to ' + identifier);
  }

  /**
   * An issued RFC 8705 client certificate's three files, once.
   *
   * @param answer - `issue-tls-client-certificate`'s answer
   * @param fields - the form's fields
   * @param back - the page the form was on
   * @returns the HTML
   */
  static tlsClientCertificate(answer: Json, fields: Json,
                              back: string): string {
    const files = answer.files;
    const cert = answer.certificate || {};
    const identifier = String((answer.application &&
                               answer.application.identifier) ||
                              WebAnswers.one(fields, 'application'));
    const link = function (file, href) {
      return '<a class="btn" download="' + kit.esc(file.name) + '" href="' +
        kit.esc(href) + '">Download ' + kit.esc(file.name) + '</a>';
    };
    return kit.warn('<p><strong>This is the only time these files can be ' +
      'downloaded.</strong> The private key is not kept by this service — ' +
      'not on the application&rsquo;s entry, not in the certificate ' +
      'register — and nothing on this console or on <code>/admin-api</code> ' +
      'hands it out again. If it is lost, revoke the certificate and issue ' +
      'another.</p><p>' +
      link(files.pkcs12, 'data:' + files.pkcs12.mime + ';base64,' +
                         files.pkcs12.base64) + ' ' +
      link(files.key, WebAnswers.dataUriOf(files.key.mime, files.key.text)) +
      ' ' +
      link(files.chain, WebAnswers.dataUriOf(files.chain.mime,
                                             files.chain.text)) +
      '</p>', 'The private key, once') +
      '<table><tr><th>Issued to</th><td><code>' + kit.esc(cert.subject) +
      '</code><div class="sub">subjectAltName <code>' +
      kit.esc(cert.implicitName) + '</code></div></td></tr>' +
      '<tr><th>Serial</th><td><code>' + kit.esc(cert.serialHex) +
      '</code></td></tr><tr><th>SHA-256 thumbprint</th><td><code>' +
      kit.esc(cert.thumbprint) + '</code></td></tr><tr><th>Key</th><td>' +
      kit.esc(cert.keyAlg) + '</td></tr><tr><th>Good until</th><td><code>' +
      kit.esc(cert.notAfter) + '</code></td></tr></table>' +
      kit.note('<strong>How the application uses it.</strong> Present it ' +
      'on the TLS connection to the token endpoint with <code>client_id=' +
      kit.esc(identifier) + '</code> and a ' +
      '<code>token_endpoint_auth_method</code> of ' +
      '<code>tls_client_auth</code> on the entry: RFC 8705 section 2.1 ' +
      'authenticates it because this realm issued it to this application, ' +
      'with nothing else registered. Every access token issued on that ' +
      'connection carries <code>cnf["x5t#S256"]</code> of this certificate ' +
      '(section 3), so the application presents the same certificate to ' +
      'the resource servers. <code>curl --cert ' + kit.esc(files.chain.name) +
      ' --key ' + kit.esc(files.key.name) + ' --pass &lt;file password&gt; ' +
      '-d grant_type=client_credentials -d client_id=' + kit.esc(identifier) +
      ' &lt;base&gt;/oauth2/token</code>') +
      WebAnswers.backButton(back, 'Back to ' + identifier);
  }

  /**
   * A remote PEP's listener certificate and its private key, once.
   *
   * @param result - `issue-pep-certificate`'s answer
   * @returns the HTML
   */
  static pepCertificate(result: Json): string {
    return kit.note('<p>' + kit.esc(result.what) + '</p>') +
      '<table><tr><th>PEP</th><td><code>' + kit.esc(result.pep) +
      '</code></td></tr><tr><th>Realm</th><td><code>' +
      kit.esc(result.realm) + '</code></td></tr><tr><th>Serial</th><td>' +
      '<code>' + kit.esc(result.serialHex) + '</code></td></tr>' +
      '<tr><th>Names</th><td>' + kit.esc([].concat(result.dnsNames || [],
        result.ipAddresses || []).join(', ')) + '</td></tr>' +
      '<tr><th>Valid until</th><td>' + kit.esc(result.notAfter) +
      '</td></tr></table>' +
      kit.warn('<p>This is the only time this service will show you this ' +
        'key. It is not on the PEP&rsquo;s entry and nothing in this ' +
        'console or in <code>/admin-api</code> opens it again. Save it as ' +
        'the file <code>PEP_HTTPS_KEY</code> names.</p><pre>' +
        kit.esc(result.privateKeyPem) + '</pre>', 'The private key, once') +
      '<p>The certificate followed by its chain (the Issuing CA and this ' +
      'realm&rsquo;s Intermediate) &mdash; the file ' +
      '<code>PEP_HTTPS_CERT</code> names:</p><pre>' +
      kit.esc(result.fullChainPem) + '</pre>' +
      '<p>The anchor a client of that listener installs &mdash; this ' +
      'service&rsquo;s Root CA, which the chain deliberately leaves ' +
      'out:</p><pre>' + kit.esc(result.anchorPem) + '</pre>' +
      WebAnswers.backButton('/admin/xacml/peps', 'Back to Remote PEPs');
  }

  /**
   * A person's assertion signing key pair (RFC 7523 or RFC 7522), once.
   *
   * @param result - the PKI issue's answer, `target=person`
   * @param fields - the form's fields
   * @param back - the page the form was on
   * @returns the HTML
   */
  static personKey(result: Json, fields: Json, back: string): string {
    const saml = result.purpose === 'saml';
    const message = String(result.why || result.message || 'Done.');
    return kit.note(kit.esc(message).replace(/\*\*(.+?)\*\*/g,
                                             '<strong>$1</strong>')) +
      kit.warn('<p>This is the only time this service will show you this ' +
        'key. It is sealed on <code>' + kit.esc(String(result.person)) +
        '</code>’s entry as <code>' +
        (saml ? 'stsSamlAssertionPrivateKey' : 'stsAssertionPrivateKey') +
        '</code> and nothing in this console or in <code>/admin-api</code> ' +
        'opens it again. Copy it now; issuing again replaces it.</p>' +
        (saml
          // THE RFC 7522 SHAPE: what the person signs is an <Assertion>.
          ? '<p>The assertion it signs carries an <code>&lt;Issuer&gt;' +
            '</code> and a <code>&lt;Subject&gt;</code> of <code>' +
            kit.esc(String(result.issuer)) + '</code>, an ' +
            '<code>&lt;AudienceRestriction&gt;</code> naming this ' +
            'service’s token endpoint, a bearer ' +
            '<code>&lt;SubjectConfirmation&gt;</code>, a ' +
            '<code>NotOnOrAfter</code> and an <code>ID</code>, is signed ' +
            'with an XML Signature over the <code>&lt;Assertion&gt;</code>, ' +
            'and is presented as <code>grant_type=urn:ietf:params:oauth:' +
            'grant-type:saml2-bearer</code> with ' +
            '<code>assertion=&lt;base64url&gt;</code>. The certificate’s ' +
            'thumbprint is <code>' + kit.esc(String(result.thumbprint)) +
            '</code>.</p>'
          : '<p>The assertion it signs carries <code>iss</code> and ' +
            '<code>sub</code> of <code>' + kit.esc(String(result.issuer)) +
            '</code>, an <code>aud</code> of this service’s token endpoint ' +
            'or issuer, an <code>exp</code> and a <code>jti</code>, and is ' +
            'presented as <code>grant_type=urn:ietf:params:oauth:' +
            'grant-type:jwt-bearer</code> with <code>assertion=&lt;the ' +
            'JWT&gt;</code>. <code>kid</code> is <code>' +
            kit.esc(String(result.kid)) + '</code> and the algorithm is ' +
            '<code>' + kit.esc(String(result.jwsAlg)) + '</code>.</p>') +
        '<pre>' + kit.esc(String(result.privateKeyPem)) + '</pre>' +
        '<p>The certificate, which is public and is also on the entry:</p>' +
        '<pre>' + kit.esc(String(result.certificatePem)) + '</pre>',
        'The private key, once') +
      WebAnswers.backButton(back, WebAnswers.one(fields, 'identifier')
        ? 'Back to ' + WebAnswers.one(fields, 'identifier').trim()
        : 'Back');
  }
}

export = WebAnswers;
