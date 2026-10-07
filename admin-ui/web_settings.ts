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
   * @returns the phrase as plain text
   */
  static sourceNote(setting, context) {
    if (setting.source === 'override') {
      return 'set here, ' + SettingsForms.overrideKept(context, setting.key);
    }
    if (setting.source === 'env') {
      return 'from ' + setting.env;
    }
    if (setting.source === 'env-legacy') {
      return 'from ' + setting.legacyEnv + ' (the legacy variable)';
    }
    if (setting.source === 'appconfig') {
      return 'from ' + (context.configFile || 'the appconfig file');
    }
    if (setting.source === 'defaults') {
      return 'from ' + context.defaultsFile + ' (the default appconfig file)';
    }
    return 'derived from another setting';
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
   * @returns `kept in the store` or `in memory only`
   */
  static overrideKept(context, key?) {
    return SettingsForms.keeps(context, key) ? 'kept in the store'
      : 'in memory only';
  }

  /**
   * Says, in a sentence for a page's notes, whether a change made on it is
   * kept across a restart, and how to keep it when it is not.
   *
   * @param context - the settings block's `context`: the appconfig file,
   *   the two persistence facts, the mode and the ambient realm
   * @returns the sentence as HTML
   */
  static durability(context) {
    const ctx = context || {};
    const file = '<code>' + kit.esc(ctx.configFile || 'env/local.js') +
                 '</code>';
    if (SettingsForms.keeps(ctx)) {
      return 'A change is written to the <code>persistence.mode=' +
             kit.esc(String(ctx.persistenceMode)) + '</code> store' +
             (ctx.inRealm
               ? ' with the <code>' + kit.esc(String(ctx.realmId)) +
                 '</code> realm\'s row'
               : '') +
             ' and kept across restarts; nothing rewrites ' + file +
             '. See <a href="/admin/persistence">Persistence</a>.';
    }
    return 'Changes are in memory and are gone on restart; to make one ' +
           'stick, put it in ' + file + ' or the setting\'s environment ' +
           'variable, or turn on a persistent store (<code>' +
           (ctx.inRealm ? 'persistence.realms' : 'persistence.appconfig') +
           '</code>) — see <a href="/admin/persistence">Persistence</a>.';
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
   * @returns the control as HTML
   */
  static orderedChoiceControl(setting, id) {
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
        kit.esc('Request ' + value) + '"></td>' +
        '<td><input type="number" name="' +
        kit.esc(key + '.rank.' + value) + '" value="' + (n + 1) +
        '" min="1" max="' + setting.csvValues.length + '" step="1" ' +
        'style="width:4.5em"' + off + ' aria-label="' +
        kit.esc('Preference of ' + value) + '"></td>' +
        '<td><code>' + kit.esc(value) + '</code></td>' +
        '<td class="sub">' + kit.esc(notes[value] || '') + '</td></tr>';
    }).join('');
    return '<input type="hidden" name="' + kit.esc(key + '.ordered') +
      '" value="1">' +
      '<table class="cfg-ordered"><tr><th>Request</th><th>Order</th>' +
      '<th>Value</th><th></th></tr>' + rows + '</table>' +
      kit.note('Tick what is requested and number it: <strong>1 is the ' +
        'most preferred</strong>, and an authenticator uses the first it ' +
        'supports. A number on an unticked row is ignored; two rows with ' +
        'the same number keep the order they are drawn in.');
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
   * @returns the table row as HTML
   */
  static row(setting, from, context) {
    const id = 'cfg-' + setting.key.replace(/\./g, '-');
    // The control carries the description as a tooltip, at the length a tooltip
    // holds. See the comment above the return.
    const hint = kit.tip(setting.description, Infinity);
    // AN ORDERED CHOICE (2026-10-01) is a checkbox and an order number per
    // value — `orderedChoiceControl()` — rather than a text box.
    const input = setting.type === 'csv' && setting.ordered &&
                  Array.isArray(setting.csvValues)
      ? SettingsForms.orderedChoiceControl(setting, id)
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
            kit.esc(option === '' ? '(empty — the default)' : option) +
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
        kit.esc(encodeURIComponent(setting.key)) + '">Reset</button>'
      : '';

    const source = kit.esc(SettingsForms.sourceNote(setting, context));
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
      : kit.note('<strong>Restart to apply:</strong> ' +
        kit.esc(setting.restartReason) + '.');

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
   * @returns the heading and form as HTML
   */
  static section(group, from, context) {
    const rows = group.settings.map(function (setting) {
      return SettingsForms.row(setting, from, context);
    }).join('');
    const anyEditable = group.settings.some(function (
        setting) { return setting.editable; });
    const save = anyEditable
      ? '<p><button>Save ' + kit.esc(group.group) + '</button> ' +
        '<span class="note">Applies to the next token, assertion, ticket or ' +
        'search — nothing already issued changes.</span></p>'
      : kit.note('Every setting in this section is read at startup, so ' +
        'there is nothing here to save. Change them in ' +
        kit.esc(context.configFile || 'the appconfig file') + ' or in ' +
        'the environment and restart.');
    return '<h3>' + kit.esc(group.group) + '</h3>' +
      '<form method="post" action="/admin/config">' +
      '<input type="hidden" name="action" value="set-many">' +
      '<input type="hidden" name="from" value="' +
      kit.esc(from || '/admin/config') +
      '"><table><tr><th>Setting</th><th>Value</th><th>Source</th><th></th>' +
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
   * @returns the sentence as HTML, or an empty string when no other page
   *   draws the group
   */
  static sharedNote(others) {
    if (!others.length) {
      return '';
    }
    return '<strong>These are the same settings ' +
      others.map(function (other) {
        return '<a href="' + kit.esc(other.path) + '">' +
               kit.esc(other.label) + '</a>';
      }).join(' and ') + ' draws.</strong> One setting, shown in both places ' +
      'because it governs both: a value saved here is saved there. Nothing ' +
      'is copied — both forms post to the same action against the same ' +
      'override map.';
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
   * @returns the block as HTML, or an empty string when the page owns no
   *   settings group (or none of `only`)
   */
  static forms(settings, path, only?) {
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
        (settings.sharedWith || {})[group.group] || []);
    }).filter(Boolean).map(function (text) { return kit.note(text); })
      .join('');

    const inner = '<h2>Settings</h2>' +

      kit.note('The appconfig rows that decide what this family does, on ' +
      'the page for the family rather than on <a ' +
      'href="/admin/config">Configuration</a>. They are the same settings, ' +
      'written through the same function against the same override map — ' +
      'this is a second DOOR onto them and not a second place they live, ' +
      'which is the rule <a href="/admin/token-lifetimes">Token ' +
      'lifetimes</a> was the first page here to apply. The <em>Source</em> ' +
      'column says where each value came from: a runtime override set on a ' +
      'page like this one, an environment variable, the appconfig file this ' +
      'process was started with, or the default appconfig file under it.') +

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
      (SettingsForms.keeps(context)
        ? '<div class="ok"><strong>Changes here SURVIVE A RESTART.</strong> ' +
          'This process is running with <code>persistence.mode=' +
          kit.esc(context.persistenceMode) + '</code>, so a value set ' +
          'here is written to the persistent store' +
          (context.inRealm
            ? ' with the <code>' + kit.esc(String(context.realmId)) +
              '</code> realm\'s row'
            : '') +
          ' and applied again the ' +
          'next time this service starts. It is still a runtime override ' +
          'rather than a new layer — the same setting, the same override ' +
          'map, put back through the same function — so <em>Reset</em> still ' +
          'means "fall back to the file or the environment variable", and ' +
          'the reset is written down too. Nothing rewrites ' +
          '<code>' + kit.esc(configFile) + '</code>, ' +
          'deliberately: a service that edited a file checked into a ' +
          'repository would leave a test\'s forgotten change behind ' +
          'permanently. See <a href="/admin/persistence">Persistence</a>.</div>'
        : kit.warn('<strong>Changes here are in memory and are gone on ' +
          'restart.</strong> Nothing writes to the appconfig file, ' +
          'deliberately: a service that edited a file checked into a ' +
          'repository would leave a test\'s forgotten change behind ' +
          'permanently. To make something stick, put it in ' +
          '<code>' + kit.esc(configFile) + '</code>, in ' +
          'the setting\'s environment variable, or turn on a persistent ' +
          'store' +
          (context.inRealm
            ? ' with <code>persistence.realms</code>, which keeps this ' +
              'realm\'s own values on its row'
            : '') +
          ' — see <a href="/admin/persistence">Persistence</a>, which ' +
          'is off by default.')) +

      (fixed
        ? kit.warn('<strong>' + kit.esc(String(fixed)) + ' of these ' +
          kit.esc(String(all.length)) + ' cannot be changed while this ' +
          'service runs.</strong> They are shown with their inputs disabled ' +
          'and the reason beside each, rather than hidden: they were ' +
          'consumed by the time this service was listening — a bound socket, ' +
          'a certificate\'s names, the Kerberos principal database and its ' +
          'long-term keys, the directory\'s base DN — and accepting a change ' +
          'to one would do nothing and read as having worked.')
        : '') +

      (overridden.length
        ? '<div class="ok">' + kit.esc(String(overridden.length)) + ' of ' +
          'these has a runtime override in ' +
          'force: ' + kit.codeList(overridden) + '. Each ' +
          'row\'s Reset puts it back to the value its file or environment ' +
          'variable gives it.</div>'
        : '') +

      groups.map(function (group) {
        return SettingsForms.section(group, path, context);
      }).join('') +

      kit.note('<a href="/admin/config">Configuration</a> holds the whole ' +
      'table — every setting this service has, whichever page edits it — and ' +
      'the rows that belong to no protocol. The same settings over JSON are ' +
      'at <code>' + kit.esc(path) + '?format=json</code> and ' +
      '<code>GET /admin-api/config</code>; the four actions are ' +
      '<code>POST /admin-api/config/set</code>, <code>/set-many</code>, ' +
      '<code>/reset</code> and <code>/reset-all</code>.');

    return inner;
  }
}

export = SettingsForms;
