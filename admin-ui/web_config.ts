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
    const snapshot = json;
    const overridden = snapshot.overridden.length;
    // What this page still edits: the groups with no protocol to belong to
    // (`Global`, `Key material`, `Web security`). Asked for by path rather
    // than by name, like every other page, so that moving one somewhere else
    // one day is a row in SETTING_HOMES and not an edit here.
    const mine = json.settings.groups;
    const mineCount = mine.reduce(function (n, group) {
      return n + group.settings.length;
    }, 0);

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

      kit.note('<strong>Every setting this service has lives on the page ' +
      'for the protocol it configures.</strong> This page is the index of ' +
      'that — and the form for the ' + kit.esc(String(mineCount)) + ' ' +
      'rows that belong to no protocol, which are facts about the process ' +
      'rather than about anything it speaks. It was ' +
      'all ' + kit.esc(String(snapshot.settingCount)) + ' of them ' +
      'until 2026-08-27; what moved is where they are DRAWN, and nothing ' +
      'about what they do or how they are read.') +

      kit.note('A value can arrive from four places and the ' +
      '<em>Source</em> column on every one of these pages says which: a ' +
      'runtime override set on the page, an environment variable, the ' +
      'appconfig file this process was started with ' +
      '(<code>' + kit.esc(snapshot.configFile || '(none)') + '</code>), ' +
      'or ' +
      '<code>' + kit.esc(snapshot.defaultsFile) + '</code> — the default ' +
      'appconfig file that one is unioned on top of. Higher beats lower, ' +
      'so an environment variable set on the container still wins over the ' +
      'file — which is what keeps every existing deployment working ' +
      'unchanged.') +

      kit.note('<strong>There is no fifth place.</strong> A setting with ' +
      'no value in either appconfig file and no environment variable stops ' +
      'this service from starting, by name, rather than falling back to a ' +
      'constant buried in a module. So every value on these pages is one ' +
      'somebody can find in a file — which is what makes the ' +
      '<em>Source</em> column worth reading.') +

      kit.warn('<strong>Changes are in memory and are gone on ' +
      'restart.</strong> Nothing writes to the appconfig file. That is the ' +
      'same arrangement as the custom claims and the credential claims ' +
      'next door, and it is deliberate: a service that edited a file ' +
      'checked into a repository would leave a test\'s forgotten change ' +
      'behind permanently. To make something stick, put it in ' +
      '<code>' + kit.esc(snapshot.configFile || 'env/local.js') +
      '</code>.') +

      '<h2>' + kit.esc(String(snapshot.settingCount)) + ' settings, ' +
      kit.esc(String(snapshot.editableCount)) + ' of them changeable ' +
      'while this service runs</h2>' +

      (overridden
        ? '<div class="ok">' + kit.esc(String(overridden)) + ' runtime ' +
          'override(s) in force, anywhere in the ' +
          'service: ' + kit.codeList(snapshot.overridden) + '. ' +
          '<form method="post" action="/admin/config" ' +
          'class="inline"><input type="hidden" name="action" ' +
          'value="reset-all"><button class="secondary">Reset ' +
          'all</button></form></div>'
        : kit.note('No runtime overrides are in force anywhere in this ' +
          'service: every value is coming from the environment or from one ' +
          'of the two appconfig files.')) +

      kit.note('<strong>Reset all is here and on no protocol ' +
      'page</strong>, because it clears every override in the service and ' +
      'not only the ones below it. A button that reached that far from the ' +
      'Kerberos page would be the one control in this console whose blast ' +
      'radius was invisible from where it was pressed.') +

      '<h2>Where every setting is edited</h2>' +
      kit.note('The whole table, group by group, in the order ' +
      '<code>config.js</code> declares them. The <em>Page</em> column is ' +
      'where that group\'s form is drawn; the counts are of the group, and ' +
      '<em>Overridden</em> is how many of them have a runtime override in ' +
      'force right now.') +
      '<table><thead><tr><th>Group</th><th class="num">Settings</th>' +
      '<th class="num">Restart-only</th><th class="num">Overridden</th>' +
      '<th>Page</th></tr></thead><tbody>' +
      snapshot.groups.map(function (group) {
        return ConfigPage.configHomeRow(group, json.homes);
      }).join('') +
      '</tbody></table>' +

      SettingsForms.forms(json.settings, '/admin/config') +

      kit.note('The whole table over JSON — every setting, whichever page ' +
      'edits it — is at <code>/admin/config?format=json</code> and ' +
      '<code>GET /admin-api/config</code>; the four actions on these pages ' +
      'are <code>POST /admin-api/config/set</code>, ' +
      '<code>/set-many</code>, <code>/reset</code> and ' +
      '<code>/reset-all</code>.');

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
   * @returns the row as HTML
   */
  static configHomeRow(group, homes) {
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
        }).join(' and ')
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
