// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_settings.ts
//
// ---------------------------------------------------------------------------
// THE SETTINGS BLOCK, DRAWN FROM ITS VIEW ALONE (#446, 2026-10-05).
//
// Every console page that owns settings draws them with one block: the lead
// notes, then a form per group. This module draws that block from the
// `settings` member the page's management API operation answers — the same
// described rows `GET /admin-api/config` returns, filtered to the page — so
// the static console draws in a browser what the server-rendered one draws
// here.
//
// THREE THINGS THE BLOCK SAID CAME FROM THE PROCESS, AND NOW ARRIVE IN THE
// VIEW, because a browser has none of them:
//
//   * the appconfig file's name and the default file's, which the Source
//     column and two of the notes name (`context.configFile`,
//     `context.defaultsFile` — `GET /admin-api/config` already reported
//     both);
//   * whether an override survives a restart, and the persistence mode that
//     says so (`context.persistsAppconfig`, `context.persistenceMode`) —
//     and, since 2026-10-07, `context.persistsRealms`, `context.inRealm` and
//     `context.realmId`, because a write inside a non-default realm lands on
//     the realm's row (`keeps()` below);
//   * which other pages draw the same group (`sharedWith`), which is
//     `SETTING_HOMES` and the navigation's labels.
//
// THE TWO FALLBACKS FOR AN UNNAMED APPCONFIG FILE ARE KEPT AS THEY WERE: the
// lead names `env/local.js`, a file a reader can open, where the Source
// column and a read-only section's note say "the appconfig file". They are
// two sentences written at two times; this move changes no page's text, and
// reconciling them is a change to the console rather than to where it is
// drawn.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// Its methods were `AdminConsole`'s in `admin-ui/admin.ts` — `sourceNote`,
// `orderedChoiceControl`, `configRow` (`row()` here), `configSection`
// (`section()`), `configFormsFor` (`forms()`) and the wording of
// `sharedSettingNote` — moved with their comments. That class keeps
// `configFormsFor()`, which calls `forms()` with the block passed through
// JSON, and `sourceNote()`, for two tables that draw a Source column of
// their own.
// ---------------------------------------------------------------------------

import kit = require('./web_kit');

/**
 * Draws the Settings block a console page carries, from the `settings`
 * member of that page's management API answer.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class SettingsForms {
  // The five sources, as a phrase a reader can act on. `env-legacy` is its own
  // case rather than being folded into `env`, because the variable it names is
  // not the one the rest of the row talks about — being told the value comes
  // from "the environment" while STS_SAML_ISSUER is unset is the kind of true
  // answer that costs twenty minutes.
  //
  // `defaults` is a case for exactly the same reason. The appconfig layer is
  // TWO files unioned — env/defaults.js, and whatever CONFIG_FILE names over it
  // — and telling somebody a value comes from "the appconfig file" when their
  // file does not mention it would send them to edit a line that is not there.
  // So the two halves of that layer are named separately and each names its own
  // file.
  //
  // The last line is now unreachable for anything but a `derived` setting:
  // config.js refuses to start when a non-derived setting has no value in
  // either file and no environment variable. It stays because the three derived
  // ones DO resolve through their `dflt`, which is a function of a neighbour
  // rather than a literal anybody could have written in a file.
  /**
   * Words where a setting's value came from: a runtime override, an
   * environment variable, the legacy variable, the appconfig file, the
   * default appconfig file, or another setting.
   *
   * @param setting - the described setting
   * @param context - the settings block's `context`: the two file names
   * @param t - the page's translator (#539); optional, the default when
   *   omitted
   * @returns the phrase as plain text
   */
  static sourceNote(setting, context, t?) {
    // A STATIC HELPER HAS NO `ctx` (#539), so its caller hands it the page's
    // translator; a caller that has not been given one yet gets the default.
    t = t || kit.context().t;
    // String() keeps a missing name drawn as it always was ("undefined"),
    // where a message parameter would draw nothing.
    if (setting.source === 'override') {
      return t.text('consoleSettings.source.override',
        { kept: SettingsForms.overrideKept(context, setting.key, t) });
    }
    if (setting.source === 'env') {
      return t.text('consoleSettings.source.env', { env: String(setting.env) });
    }
    if (setting.source === 'env-legacy') {
      return t.text('consoleSettings.source.envLegacy',
        { env: String(setting.legacyEnv) });
    }
    if (setting.source === 'appconfig') {
      return t.text('consoleSettings.source.appconfig',
        { file: context.configFile ||
          t.text('consoleSettings.source.theAppconfigFile') });
    }
    if (setting.source === 'defaults') {
      return t.text('consoleSettings.source.defaults',
        { file: String(context.defaultsFile) });
    }
    return t.text('consoleSettings.source.derived');
  }

  // WHERE AN OVERRIDE SET HERE IS HELD, IN TWO WORDS AND IN ONE SENTENCE
  // (rcbj, 2026-10-07). The Source column said "in memory only" and the
  // shorter settings pages — Token lifetimes, SAML assertions, Configuration
  // — said "Changes are in memory and are gone on restart" unconditionally,
  // which has been wrong on every persistent store since 2026-08-27.
  //
  // ONE RULE, `keeps()`, AND IT IS THE REPLIES' RULE. A write made while a
  // non-default realm is ambient lands on the realm's row and is kept when
  // `persistsRealms` is; every other write lands in the process-wide map and
  // is kept when `persistsAppconfig` is — what
  // `AdminActions.overrideDurability()` words a reply by. The two `realms.*`
  // rows always land process-wide, so `keeps()` takes the key when it has
  // one. The block's lead note below, these two and the Source column all ask
  // it, so no page can disagree with the reply its own Save gets back.
  /**
   * Says whether an override written from a page with this context is kept
   * across a restart.
   *
   * @param context - the settings block's `context`
   * @param key - the setting, when the question is about one; optional
   * @returns true when the store under the write persists it
   */
  static keeps(context, key?) {
    const ctx = context || {};
    const inRealm = !!ctx.inRealm && String(key || '').indexOf('realms.') !== 0;
    return inRealm ? !!ctx.persistsRealms : !!ctx.persistsAppconfig;
  }

  /**
   * Words where a runtime override set on these pages is held.
   *
   * @param context - the settings block's `context`
   * @param key - the setting, when it is about one; optional
   * @param t - the page's translator (#539); optional
   * @returns `kept in the store` or `in memory only`, as plain text
   */
  static overrideKept(context, key?, t?) {
    t = t || kit.context().t;
    return SettingsForms.keeps(context, key)
      ? t.text('consoleSettings.kept.store')
      : t.text('consoleSettings.kept.memory');
  }

  /**
   * Says, in a sentence for a page's notes, whether a change made on it is
   * kept across a restart, and how to keep it when it is not.
   *
   * @param context - the settings block's `context`: the appconfig file,
   *   the two persistence facts, the mode and the ambient realm
   * @param t - the page's translator (#539); optional
   * @returns the sentence as HTML
   */
  static durability(context, t?) {
    t = t || kit.context().t;
    const ctx = context || {};
    const file = ctx.configFile || 'env/local.js';
    // The link is markup a message cannot carry (#539), so the words on
    // either side of it are messages of their own; the sentence's closing
    // full stop stays here, after the link.
    const persistence = '<a href="/admin/persistence">' +
      t.html('consoleSettings.persistence') + '</a>.';
    if (SettingsForms.keeps(ctx)) {
      return (ctx.inRealm
        ? t.html('consoleSettings.durability.keptRealm',
          { mode: String(ctx.persistenceMode), realm: String(ctx.realmId),
            file: file })
        : t.html('consoleSettings.durability.kept',
          { mode: String(ctx.persistenceMode), file: file })) +
        persistence;
    }
    return t.html('consoleSettings.durability.memory',
      { file: file,
        store: ctx.inRealm ? 'persistence.realms' : 'persistence.appconfig' }) +
      persistence;
  }

  // ---------------------------------------------------------------------------
  // AN ORDERED CHOICE FROM A CLOSED LIST (2026-10-01, rcbj: "explicitly
  // choose, by checkboxes, which webauthn / ctap algorithms are requested and
  // an order of preference"). A `csv` row marked `ordered` (only
  // `webauthn.algorithms` today) is drawn as a table: one row per value, a
  // checkbox that says whether it is requested and a number that says where
  // it comes in the preference order, with the value's own note beside it.
  // Chosen values are drawn first, in their current order, numbered 1 to N;
  // the rest follow in the list's own order, numbered on from N + 1, so
  // ticking one puts it last unless its number is changed.
  //
  // NO SCRIPT, for this console's reason: drag-and-drop or Up and Down
  // buttons would need a script or a round trip per move, and a number per
  // row is a whole re-ordering in one save. The fields are
  // `<key>.pick.<value>` and `<key>.rank.<value>`, with `<key>.ordered`
  // beside them so a save that ticks nothing is told apart from a form that
  // does not hold this row; `foldOrderedChoices()` turns them back into the
  // setting's one comma-separated value before the save is checked.
  // ---------------------------------------------------------------------------
  /**
   * Draws an ordered choice from a closed list as a table of checkboxes and
   * order numbers.
   *
   * @param setting - the described setting (`ordered`, `csvValues`)
   * @param id - the id the row's label points at, given to the first box
   * @param t - the page's translator (#539); optional
   * @returns the control as HTML
   */
  static orderedChoiceControl(setting, id, t?) {
    t = t || kit.context().t;
    const chosen = String(setting.text || '').split(',')
      .map(function (one) { return one.trim(); })
      .filter(function (one) {
        return one !== '' && setting.csvValues.indexOf(one) >= 0;
      });
    const rest = setting.csvValues.filter(function (one) {
      return chosen.indexOf(one) < 0;
    });
    const notes = setting.csvValueNotes || {};
    const off = setting.editable ? '' : ' disabled';
    const key = String(setting.key);
    const rows = chosen.concat(rest).map(function (value, n) {
      const picked = chosen.indexOf(value) >= 0;
      return '<tr><td><input type="checkbox" name="' +
        kit.esc(key + '.pick.' + value) + '" value="1"' +
        (n === 0 ? ' id="' + kit.esc(id) + '"' : '') +
        (picked ? ' checked' : '') + off + ' aria-label="' +
        kit.esc(t.text('consoleSettings.ordered.requestValue',
          { value: value })) + '"></td>' +
        '<td><input type="number" name="' +
        kit.esc(key + '.rank.' + value) + '" value="' + (n + 1) +
        '" min="1" max="' + setting.csvValues.length + '" step="1" ' +
        'style="width:4.5em"' + off + ' aria-label="' +
        kit.esc(t.text('consoleSettings.ordered.preferenceOf',
          { value: value })) + '"></td>' +
        '<td><code>' + kit.esc(value) + '</code></td>' +
        '<td class="sub">' + kit.esc(notes[value] || '') + '</td></tr>';
    }).join('');
    return '<input type="hidden" name="' + kit.esc(key + '.ordered') +
      '" value="1">' +
      '<table class="cfg-ordered"><tr><th>' +
      t.html('consoleSettings.ordered.request') + '</th><th>' +
      t.html('consoleSettings.ordered.order') + '</th>' +
      '<th>' + t.html('consoleSettings.ordered.value') + '</th><th></th></tr>' +
      rows + '</table>' +
      kit.note(t.html('consoleSettings.ordered.note'));
  }

  /**
   * Draws one setting as a table row: its key with the description as a
   * tooltip, its control, its source and, when overridden, a Reset button.
   *
   * A restart-only setting is drawn with its control disabled and the
   * reason beside it.
   *
   * @param setting - the described setting
   * @param from - the page the row is drawn on; not read by the row itself
   * @param context - the settings block's `context`
   * @param t - the page's translator (#539); optional
   * @returns the table row as HTML
   */
  static row(setting, from, context, t?) {
    t = t || kit.context().t;
    const id = 'cfg-' + setting.key.replace(/\./g, '-');
    // The control carries the description as a tooltip, at the length a tooltip
    // holds. See the comment above the return.
    const hint = kit.tip(setting.description, Infinity);
    // AN ORDERED CHOICE (2026-10-01) is a checkbox and an order number per
    // value — `orderedChoiceControl()` — rather than a text box.
    const input = setting.type === 'csv' && setting.ordered &&
                  Array.isArray(setting.csvValues)
      ? SettingsForms.orderedChoiceControl(setting, id, t)
      : setting.type === 'enum'
      ? '<select name="' + kit.esc(setting.key) + '" id="' + kit.esc(id) +
        '"' + hint +
        (setting.editable ? '' : ' disabled') + '>' +
        setting.enumValues.map(function (option) {
          // An enum whose set holds the empty string (#86 made
          // `pki.signatureAlgorithm` one) draws it as what it means rather
          // than as a blank line.
          return '<option value="' + kit.esc(option) + '"' +
            (option === setting.text ? ' selected' : '') + '>' +
            kit.esc(option === ''
              ? t.text('consoleSettings.row.emptyDefault') : option) +
                 '</option>';
        }).join('') + '</select>'
      : (setting.type === 'bool'
        ? '<select name="' + kit.esc(setting.key) + '" id="' + kit.esc(id) +
          '"' + hint +
          (setting.editable ? '' : ' disabled') + '>' +
          ['true', 'false'].map(function (option) {
            return '<option value="' + option + '"' +
              (option === setting.text ? ' selected' : '') + '>' + option +
                   '</option>';
          }).join('') + '</select>'
        : '<input type="text" name="' + kit.esc(setting.key) + '" id="' +
          kit.esc(id) +
          '"' +
          hint + ' size="34" value="' + kit.esc(setting.text) + '"' +
          (setting.editable ? '' : ' disabled') + '>');

    // THE RESET BUTTON IS A `formaction`, AND IT USED TO BE A NESTED `<form>`
    // THAT NO BROWSER EVER CREATED. This row is inside the section's form, and
    // the HTML parser DROPS a `<form>` start tag inside another form — the
    // element is never created and its children are adopted by the outer form.
    // So the row's `action=reset` and `key` hidden inputs became fields of the
    // SECTION's form, `parseBody()` takes the last value of a repeated name,
    // and the section's Save button therefore performed a RESET of the last
    // overridden key instead of saving. Nothing failed: the page reloaded with
    // a cheerful message about the thing it had just done instead of the thing
    // it was asked to do. It was found by dumping the parsed DOM rather than by
    // reading the markup, which is the only way this class of defect is ever
    // found.
    //
    // `formaction` is the fix and it needs no script: the button submits the
    // same form to a different URL, and the key rides in that URL where it
    // cannot be confused with a field. THE KEY IS IN THE QUERY STRING AND NOT
    // IN A HIDDEN INPUT for exactly that reason.
    //
    // It also fixes what pressing ENTER in a text box does. A form with no
    // hidden `action` and two named submit buttons would submit the FIRST one
    // on Enter — a Reset — so the hidden `action=set-many` stays and the
    // buttons carry no name at all: Enter posts to the form's own action and
    // saves.
    //
    // `form-action` is deliberately absent from this service's CSP (see
    // `common/app.js`), so nothing here is relaxed to allow it.
    const reset = setting.overridden
      ? '<button class="secondary" formaction="/admin/config?reset=' +
        kit.esc(encodeURIComponent(setting.key)) + '">' +
        t.html('consoleSettings.row.reset') + '</button>'
      : '';

    const source = kit.esc(SettingsForms.sourceNote(setting, context, t));
    const provenance = setting.overridden
      ? '<strong>' + source + '</strong>'
      : source;

    // Named `restart` and not `note`, which it was until the folds arrived: a
    // local called `note` shadows the helper of that name for the whole
    // function, and the row then fails to render with `Cannot access 'note'
    // before initialization` — at request time, on one page, which is the
    // slowest possible way to find out.
    const restart = setting.editable
      ? ''
      : kit.note('<strong>' + t.html('consoleSettings.row.restart') +
        '</strong> ' + kit.esc(setting.restartReason) + '.');

    // THE DESCRIPTION IS THE TOOLTIP AND THERE IS NO LONGER A FOLD
    // (2026-09-05).
    //
    // It was a fold with the setting's short label as its summary, and the
    // input carried a 190-character teaser of the same text. That was the right
    // shape while a tooltip was a PREVIEW of something the reader could go and
    // read — but it meant 152 summary lines on /admin/config and a summary line
    // per setting on every protocol page's Settings block, which is the bulk of
    // what was left visible after the 2026-08-26 folds.
    //
    // Both the key's label and the control now carry the WHOLE description as a
    // title, and nothing is drawn under them. **This is the one place in this
    // console where something is said only in a tooltip**, and it is deliberate
    // rather than an oversight — see the paragraph in `admin-ui/CLAUDE.md` that
    // used to say the opposite. What pays for it is that a setting's
    // description is also on `/admin/config`'s own JSON view, in
    // `GET /admin-api/config`, and in docs/configuration.md's table, so the
    // text has three other doors that a keyboard or a screen reader can
    // reach. A field whose prose has NO other door does not get this
    // treatment.
    return '<tr>' +
      '<td><label for="' + kit.esc(id) + '"' +
      kit.tip(setting.description, Infinity) +
      '><code>' + kit.esc(setting.key) + '</code></label>' +
      restart + '</td>' +
      '<td>' + input + '</td>' +
      '<td>' + provenance + '</td>' +
      '<td>' + reset + '</td></tr>';
  }

  /**
   * Draws one settings group as a form that posts every row at once
   * (set-many) to /admin/config, with a Save button when any row is
   * editable.
   *
   * @param group - the described settings group
   * @param from - optional; the page to return to after a save
   * @param context - the settings block's `context`
   * @param t - the page's translator (#539); optional
   * @returns the heading and form as HTML
   */
  static section(group, from, context, t?) {
    t = t || kit.context().t;
    const rows = group.settings.map(function (setting) {
      return SettingsForms.row(setting, from, context, t);
    }).join('');
    const anyEditable = group.settings.some(function (
        setting) { return setting.editable; });
    const save = anyEditable
      ? '<p><button>' + t.html('consoleSettings.section.save',
        { group: group.group }) + '</button> ' +
        '<span class="note">' + t.html('consoleSettings.section.applies') +
        '</span></p>'
      : kit.note(t.html('consoleSettings.section.readAtStartup',
        { file: context.configFile ||
          t.text('consoleSettings.source.theAppconfigFile') }));
    return '<h3>' + kit.esc(group.group) + '</h3>' +
      '<form method="post" action="/admin/config">' +
      '<input type="hidden" name="action" value="set-many">' +
      '<input type="hidden" name="from" value="' +
      kit.esc(from || '/admin/config') +
      '"><table><tr><th>' + t.html('consoleSettings.section.setting') +
      '</th><th>' + t.html('consoleSettings.section.value') + '</th><th>' +
      t.html('consoleSettings.section.source') + '</th><th></th>' +
      '</tr>' +
      rows + '</table>' + save + '</form>';
  }

  // The other pages a group of these settings is also drawn on, as a sentence,
  // or '' when there are none. Only `SAML` has any today; the sentence is
  // derived so that a second shared group cannot arrive without being
  // announced. WHICH pages is the server's to say — it is `SETTING_HOMES` and
  // the navigation's labels, neither of which a browser holds — so it arrives
  // in the block's `sharedWith` and only the wording is here.
  /**
   * Words the note that a settings group is also drawn on other pages,
   * linking to each.
   *
   * @param others - the other pages, each `{ path, label }`
   * @param t - the page's translator (#539); optional
   * @returns the sentence as HTML, or an empty string when no other page
   *   draws the group
   */
  static sharedNote(others, t?) {
    t = t || kit.context().t;
    if (!others.length) {
      return '';
    }
    // The links are markup a message cannot carry (#539): the words before,
    // between and after them are messages, spaces included.
    return '<strong>' + t.html('consoleSettings.shared.before') +
      others.map(function (other) {
        return '<a href="' + kit.esc(other.path) + '">' +
               kit.esc(other.label) + '</a>';
      }).join(t.html('consoleSettings.shared.and')) +
      t.html('consoleSettings.shared.after') + '</strong>' +
      t.html('consoleSettings.shared.rest');
  }

  // The block itself.
  /**
   * Draws the Settings block a console page carries: the lead notes on
   * persistence, restart-only rows and overrides, then one section form per
   * group the page owns.
   *
   * @param settings - the page's settings block, as the management API
   *   answers it (`groups`, `context`, `sharedWith`)
   * @param path - the page's path
   * @param only - optional; the names of the groups to draw, for a page that
   *   puts each of its groups on a tab of its own (/admin/listeners, #423)
   * @param t - the page's translator (#539); optional, the default when
   *   omitted — a page passes its `ctx.t`
   * @returns the block as HTML, or an empty string when the page owns no
   *   settings group (or none of `only`)
   */
  static forms(settings, path, only?, t?) {
    t = t || kit.context().t;
    const groups = (settings.groups || []).filter(function (group) {
      return !Array.isArray(only) || only.indexOf(group.group) >= 0;
    });
    if (!groups.length) {
      return '';
    }

    const all = groups.reduce(function (rows, group) {
      return rows.concat(group.settings);
    }, []);
    const fixed =
        all.filter(function (setting) { return !setting.editable; }).length;
    const overridden =
        all.filter(function (setting) { return setting.overridden; })
                          .map(function (setting) { return setting.key; });
    const context = settings.context || {};
    const configFile = context.configFile || 'env/local.js';

    const shared = groups.map(function (group) {
      return SettingsForms.sharedNote(
        (settings.sharedWith || {})[group.group] || [], t);
    }).filter(Boolean).map(function (text) { return kit.note(text); })
      .join('');

    // The persistence link, which several sentences below end with; the
    // full stop or clause after it is the message that follows (#539).
    const persistence = '<a href="/admin/persistence">' +
      t.html('consoleSettings.persistence') + '</a>';

    const inner = '<h2>' + t.html('consoleSettings.forms.heading') + '</h2>' +

      kit.note(t.html('consoleSettings.forms.lead1') +
      '<a href="/admin/config">' + t.html('consoleSettings.configuration') +
      '</a>' + t.html('consoleSettings.forms.lead2') +
      '<a href="/admin/token-lifetimes">' +
      t.html('consoleSettings.tokenLifetimes') + '</a>' +
      t.html('consoleSettings.forms.lead3')) +

      shared +

      // ---------------------------------------------------------------------
      // THIS PARAGRAPH USED TO BE ONE SENTENCE AND IT WAS TRUE FOR THE WHOLE
      // LIFE OF THIS SERVICE UNTIL 2026-08-27.
      //
      // "Changes here are in memory and are gone on restart" is now true only
      // in the default mode, and it is drawn on EVERY settings page in this
      // console — so leaving it would have made the most-repeated sentence in
      // the console the wrong one, on a service whose premise is that the prose
      // is more trustworthy than the code.
      //
      // Both branches are written out rather than one being patched with a
      // clause, because they are different advice: with no persistent store the
      // reader is told to edit the appconfig file, and with one they are told
      // that this IS the durable door and where the value went.
      //
      // WHAT DID NOT CHANGE is the reason nothing here rewrites the appconfig
      // FILE, which is the same in both modes and is worth keeping said: a
      // service that edited a file checked into a repository would leave a
      // test's forgotten change behind permanently. The durable overrides go to
      // the persistent store instead, which is a place nothing is checked in
      // from.
      // ---------------------------------------------------------------------
      // SINCE 2026-10-07 it asks `keeps()`, the replies' rule: inside a
      // non-default realm a value set here lands on the realm's row, so
      // `persistsRealms` decides it there and the note names the realm.
      // The realm's clause is a whole second message rather than a piece
      // spliced in (#539), so a translation can put it where its grammar
      // wants it.
      (SettingsForms.keeps(context)
        ? '<div class="ok">' + (context.inRealm
          ? t.html('consoleSettings.forms.keptRealm',
            { mode: context.persistenceMode, realm: String(context.realmId),
              file: configFile })
          : t.html('consoleSettings.forms.kept',
            { mode: context.persistenceMode, file: configFile })) +
          persistence + '.</div>'
        : kit.warn((context.inRealm
          ? t.html('consoleSettings.forms.memoryRealm', { file: configFile })
          : t.html('consoleSettings.forms.memory', { file: configFile })) +
          persistence + t.html('consoleSettings.forms.memoryEnd'))) +

      (fixed
        ? kit.warn(t.html('consoleSettings.forms.fixed',
          { fixed: String(fixed), all: String(all.length) }))
        : '') +

      (overridden.length
        ? '<div class="ok">' + t.html('consoleSettings.forms.overridden',
          { n: String(overridden.length) }) + kit.codeList(overridden) +
          t.html('consoleSettings.forms.overriddenEnd') + '</div>'
        : '') +

      groups.map(function (group) {
        return SettingsForms.section(group, path, context, t);
      }).join('') +

      kit.note('<a href="/admin/config">' +
      t.html('consoleSettings.configuration') + '</a>' +
      t.html('consoleSettings.forms.tail', { path: path }));

    return inner;
  }
}

export = SettingsForms;
