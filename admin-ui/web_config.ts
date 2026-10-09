// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_config.ts
//
// ---------------------------------------------------------------------------
// SERVER CONFIGURATION → CONFIGURATION, DRAWN FROM ITS VIEW ALONE (#446,
// 2026-10-05).
//
// Draws Configuration from the answer of `GET /admin-api/config`: where every
// group of settings is drawn, and the form for the rows that belong to no
// protocol.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// It was drawn inside the route of `/admin/config` in `admin-ui/admin.ts`,
// which still draws the page until the console's cutover by calling this with
// its view passed through JSON.
// ---------------------------------------------------------------------------

import kit = require('./web_kit');
import SettingsForms = require('./web_settings');

type Json = any;

/**
 * Draws Configuration from the answer of `GET /admin-api/config`: where every
 * group of settings is drawn, and the form for the rows that belong to no
 * protocol.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class ConfigPage {
  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static body(ctx, json) {
    // The page's words are its catalog's (#539); what the view answered —
    // the settings, the problems, the file names — is drawn as it came.
    const t = ctx.t;
    const snapshot = json;
    // What the settings block says about this process: the appconfig file
    // and whether an override is written down.
    const stored = (json.settings && json.settings.context) || {};
    const overridden = snapshot.overridden.length;
    // What this page still edits: the groups with no protocol to belong to
    // (`Global`, `Key material`, `Web security`). Asked for by path rather
    // than by name, like every other page, so that moving one somewhere else
    // one day is a row in SETTING_HOMES and not an edit here.
    const mine = json.settings.groups;
    const mineCount = mine.reduce(function (n, group) {
      return n + group.settings.length;
    }, 0);

    // The problem banner stays English: it reports a fault (#539's rule
    // that every error is English), and its items are the view's.
    const inner = (json.homeProblems.length
        ? '<div class="err"><strong>Some settings are not on any ' +
          'page.</strong><ul>' +
          json.homeProblems.map(function (problem) {
            return '<li>' + kit.esc(problem) + '</li>';
          }).join('') + '</ul>This is reported rather than hidden, in the ' +
          'same spirit as <a href="/admin/sts-metadata">Service ' +
          'metadata</a> naming a route nobody described: a setting that ' +
          'exists and appears nowhere is worse than one that is missing, ' +
          'because the service still reads it.</div>'
        : '') +

      kit.note(t.html('consoleConfig.everySettingLives',
                      { mine: String(mineCount),
                        total: String(snapshot.settingCount) })) +

      // The two file names are paths, which carry no apostrophe, so the
      // catalog's escaping draws them exactly as kit.esc() did.
      kit.note(t.html('consoleConfig.fourPlaces',
                      { configFile: snapshot.configFile || '(none)',
                        defaultsFile: snapshot.defaultsFile })) +

      kit.note(t.html('consoleConfig.noFifthPlace')) +

      // Worded from the block's own `context` (rcbj, 2026-10-07): this
      // said "in memory and gone on restart" unconditionally, which has been
      // wrong on every persistent store since 2026-08-27.
      (SettingsForms.keeps(stored)
        ? '<div class="ok">' + t.html('consoleConfig.survives') + ' ' +
          SettingsForms.durability(stored, t) + ' ' +
          t.html('consoleConfig.fileLeftAlone') + '</div>'
        : kit.warn(t.html('consoleConfig.inMemory') + ' ' +
          SettingsForms.durability(stored, t))) +

      '<h2>' + t.html('consoleConfig.settingsHeading',
                      { total: String(snapshot.settingCount),
                        editable: String(snapshot.editableCount) }) +
      '</h2>' +

      (overridden
        ? '<div class="ok">' +
          t.html('consoleConfig.overridesInForce',
                 { n: String(overridden) }) + ' ' +
          kit.codeList(snapshot.overridden) + '. ' +
          '<form method="post" action="/admin/config" ' +
          'class="inline"><input type="hidden" name="action" ' +
          'value="reset-all"><button class="secondary">' +
          t.html('consoleConfig.resetAll') + '</button></form></div>'
        : kit.note(t.html('consoleConfig.noOverrides'))) +

      kit.note(t.html('consoleConfig.resetAllHere')) +

      '<h2>' + t.html('consoleConfig.whereEdited') + '</h2>' +
      kit.note(t.html('consoleConfig.wholeTable')) +
      '<table><thead><tr><th>' + t.html('consoleConfig.thGroup') +
      '</th><th class="num">' + t.html('consoleConfig.thSettings') +
      '</th>' +
      '<th class="num">' + t.html('consoleConfig.thRestartOnly') +
      '</th><th class="num">' + t.html('consoleConfig.thOverridden') +
      '</th>' +
      '<th>' + t.html('consoleConfig.thPage') + '</th></tr></thead><tbody>' +
      snapshot.groups.map(function (group) {
        return ConfigPage.configHomeRow(group, json.homes, t);
      }).join('') +
      '</tbody></table>' +

      SettingsForms.forms(json.settings, '/admin/config', undefined,
                          t) +

      kit.note(t.html('consoleConfig.overJson'));

    return inner;
  }

  // ONE ROW OF THE INDEX: a group, its size, what is overridden in it, and the
  // page that edits it. Built from `config.groups()` and SETTING_HOMES
  // together, which is what makes a group with no home visible here rather than
  // merely absent — see checkSettingHomes(), whose findings the page prints
  // above this table.
  /**
   * Draws one settings group's row of the configuration index: its size,
   * how many are fixed and overridden, and the pages that edit it.
   *
   * A group with no SETTING_HOMES row is drawn as homeless, in red.
   *
   * @param group - the group, as `config.groups()` describes it
   * @param homes - the view's `homes`: each group's pages and labels
   * @param t - the page's translator
   * @returns the row as HTML
   */
  static configHomeRow(group, homes, t) {
    // Where the group is drawn, from the view's `homes` (#446): a page
    // drawn in a browser has no SETTING_HOMES to look in.
    const row = (homes || []).filter(function (one) {
      return one.group === group.group;
    })[0];
    const overridden = group.settings.filter(function (setting) {
      return setting.overridden;
    }).length;
    const fixed = group.settings.filter(function (setting) {
      return !setting.editable;
    }).length;
    const where = row
      ? row.pages.map(function (path, n) {
          return '<a href="' + kit.esc(path) + '">' +
                 kit.esc(row.labels[n]) + '</a>';
        }).join(t.html('consoleConfig.pagesAnd'))
      // A group with no home is a fault, and a fault is worded in English.
      : '<span class="state-invalid">nowhere — this group has no row in ' +
        'SETTING_HOMES, so nothing draws it</span>';
    return '<tr><td>' + kit.esc(group.group) + '</td>' +
      '<td class="num">' + group.settings.length + '</td>' +
      '<td class="num">' + (fixed || '') + '</td>' +
      '<td class="num">' + (overridden || '') + '</td>' +
      '<td>' + where + '</td></tr>';
  }
}

export = ConfigPage;
