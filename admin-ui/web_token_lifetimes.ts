// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_token_lifetimes.ts
//
// ---------------------------------------------------------------------------
// SERVER CONFIGURATION → TOKEN LIFETIMES, DRAWN FROM ITS VIEW ALONE (#446,
// 2026-10-05).
//
// Draws Token lifetimes from the answer of `GET /admin-api/token-lifetimes`:
// the six settings, what each issued token was given, and the warnings their
// combination earns.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// It was drawn inside the route of `/admin/token-lifetimes` in
// `admin-ui/admin.ts`, which still draws the page until the console's cutover
// by calling this with its view passed through JSON.
// ---------------------------------------------------------------------------

import kit = require('./web_kit');
import SettingsForms = require('./web_settings');

type Json = any;

// Which token kind each lifetime governs, so the page can put the count of what
// is already out there beside the number that decided it. `oauth2.clockSkewS`
// governs no kind — it is applied when a token of any kind is read back — and
// is deliberately absent rather than mapped to something plausible.
const TOKEN_LIFETIME_KINDS = {
  'oauth2.accessTokenTtlS': 'access_token',
  'oauth2.idTokenTtlS': 'id_token',
  'oauth2.refreshTokenTtlS': 'refresh_token'
};

/**
 * Draws Token lifetimes from the answer of `GET /admin-api/token-lifetimes`:
 * the six settings, what each issued token was given, and the warnings their
 * combination earns.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class TokenLifetimesPage {
  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static body(ctx, json) {
    const t = ctx.t;
    const settings = json.settings;
    const snapshot = { tokens: json.tokens, overridable: json.overridable,
                       context: json.context };
    const anyOverridden =
        settings.some(function (setting) { return setting.overridden; });

    // A sentence that runs into a link (markup with an href, which a
    // message may not carry) is split around it (#539).
    const inner = kit.note(t.html('consoleTokenLifetimes.intro') + '<a ' +
      'href="/admin/oauth2">' + t.html('consoleTokenLifetimes.introLink') +
      '</a>' + t.html('consoleTokenLifetimes.introEnd')) +

      kit.warn(t.html('consoleTokenLifetimes.nextToken') +
      '<a href="/admin/tokens">' +
      t.html('consoleTokenLifetimes.tokensPage') + '</a>' +
      t.html('consoleTokenLifetimes.nextTokenEnd') +
      SettingsForms.durability(json.context, t)) +

      TokenLifetimesPage.tokenLifetimeWarningsFor(
        json.lifetimes.accessTokenTtlS, json.lifetimes.refreshTokenTtlS,
        json.lifetimes.clockSkewS, t) +

      '<h2>' + t.html('consoleTokenLifetimes.sixHeading') + '</h2>' +
      kit.note(t.html('consoleTokenLifetimes.units')) +
      '<form method="post" action="/admin/token-lifetimes"><input ' +
      'type="hidden" name="action" ' +
      'value="set"><table><tr><th>' +
      t.html('consoleTokenLifetimes.colSetting') + '</th><th>' +
      t.html('consoleTokenLifetimes.colValue') + '</th><th>' +
      t.html('consoleTokenLifetimes.colWhichIs') + '</th><th>' +
      t.html('consoleTokenLifetimes.colPerClient') + '</th><th>' +
      t.html('consoleTokenLifetimes.colSource') + '</th><th>' +
      t.html('consoleTokenLifetimes.colHeld') + '</th></tr>' +
      settings.map(function (setting) {
        return TokenLifetimesPage.tokenLifetimeRow(setting, snapshot, t);
      })
              .join('') +
      '</table>' +
      // The caption is a fold BELOW the button rather than a span beside it,
      // and the reason is markup rather than taste: a <details> inside a <p>
      // is invalid and every browser closes the paragraph in front of it,
      // which leaves the fold outside the form it belongs to.
      '<p><button>' + t.html('consoleTokenLifetimes.save') + '</button></p>' +
      kit.note(t.html('consoleTokenLifetimes.allChecked')) +
      '</form>' +

      (anyOverridden
        ? '<div class="ok">' +
          t.html('consoleTokenLifetimes.setHere',
                 { n: String(settings.filter(function (s) {
                   return s.overridden;
                 }).length) }) +
          SettingsForms.overrideKept(json.context, undefined, t) +
          '. <form method="post" ' +
          'action="/admin/token-lifetimes" class="inline"><input ' +
          'type="hidden" name="action" value="defaults"><button ' +
          'class="secondary">' + t.html('consoleTokenLifetimes.putBack') +
          '</button></form> ' + t.html('consoleTokenLifetimes.clears') +
          '<a href="/admin/config">' +
          t.html('consoleTokenLifetimes.configuration') + '</a>' +
          t.html('consoleTokenLifetimes.clearsEnd') + '</div>'
        : kit.note(t.html('consoleTokenLifetimes.noneOverridden',
          { configFile: (json.context || {}).configFile ||
              t.text('consoleTokenLifetimes.appconfigFile'),
            defaultsFile: (json.context || {}).defaultsFile }))) +

      '<h2>' + t.html('consoleTokenLifetimes.skewHeading') + '</h2>' +
      kit.note(t.html('consoleTokenLifetimes.skewNote')) +

      '<h2>' + t.html('consoleTokenLifetimes.outHeading') + '</h2>' +
      kit.note(t.html('consoleTokenLifetimes.outNote',
                      { held: String(json.tokens.held),
                        cap: String(json.tokens.cap),
                        forgotten: String(json.tokens.forgotten) }) +
      '<a href="/admin/tokens">' +
      t.html('consoleTokenLifetimes.tokensPage') + '</a>.') +
      '<table><tr><th>' + t.html('consoleTokenLifetimes.colKind') +
      '</th><th class="num">' + t.html('consoleTokenLifetimes.colIssued') +
      '</th><th ' +
      'class="num">' + t.html('consoleTokenLifetimes.colValid') +
      '</th><th class="num">' + t.html('consoleTokenLifetimes.colExpired') +
      '</th><th ' +
      'class="num">' + t.html('consoleTokenLifetimes.colRevoked') +
      '</th><th class="num">' +
      t.html('consoleTokenLifetimes.colNotYetValid') + '</th><th ' +
      'class="num">' + t.html('consoleTokenLifetimes.colNoExpiry') +
      '</th></tr>' +
      (json.tokens.byKind.map(function (row) {
        return '<tr><td><code>' + kit.esc(row.kind) + '</code></td>' +
          '<td class="num">' + row.issued + '</td>' +
          '<td class="num state-valid">' + row.valid + '</td>' +
          '<td class="num state-expired">' + row.expired + '</td>' +
          '<td class="num state-revoked">' + row.revoked + '</td>' +
          '<td class="num state-expired">' + row.notYetValid + '</td>' +
          '<td class="num state-none">' + row.noExpiry + '</td></tr>';
      }).join('') ||
       '<tr><td colspan="7">' + t.html('consoleTokenLifetimes.noneIssued') +
       '</td></tr>') +
      '</table>' +

      '<h2>' + t.html('consoleTokenLifetimes.idleHeading') + '</h2>' +
      kit.note(t.html('consoleTokenLifetimes.idleNote') + '<a ' +
      'href="/admin/oauth2">' + t.html('consoleTokenLifetimes.oauthLink') +
      '</a>.') +

      kit.note(t.html('consoleTokenLifetimes.json'));

    return inner;
  }

  // One row of the form. A `number` input rather than the text box
  // /admin/config draws, with `min`, `max` and `step` off the setting itself —
  // the bounds are declared in config.js's table and are rendered here rather
  // than repeated, so the browser's own refusal and the server's are the same
  // three numbers. The server still checks: an input attribute is a convenience
  // for a person and no constraint at all on a JSON body or a curl.
  /**
   * Draws one row of the token lifetimes form: the control, the value in
   * words, the per-client attribute that overrides it, its source, and how
   * many tokens of its kind are valid, expired and revoked.
   *
   * @param setting - the described setting
   * @param snapshot - the statistics snapshot the token counts come from
   * @param t - the page's translator (#539)
   * @returns the table row as HTML
   */
  static tokenLifetimeRow(setting, snapshot, t) {
    const id = 'tl-' + setting.key.replace(/\./g, '-');
    const kind = TOKEN_LIFETIME_KINDS[setting.key];
    const counts = kind
      ? (snapshot.tokens.byKind.filter(function (row) {
        return row.kind === kind;
      })[0] || null)
      : null;
    const issued = counts
      ? '<span class="state-valid">' +
        t.html('consoleTokenLifetimes.nValid', { n: counts.valid }) +
        '</span>, ' +
        '<span class="state-expired">' +
        t.html('consoleTokenLifetimes.nExpired', { n: counts.expired }) +
        '</span>, ' +
        '<span class="state-revoked">' +
        t.html('consoleTokenLifetimes.nRevoked', { n: counts.revoked }) +
        '</span>'
      : '<span class="state-none">&mdash;</span>';
    // The setting's own description, on the label and on the box. It is the
    // same sentence every settings form carries as its row's tooltip since
    // 2026-09-05 (configRow()), where it used to be a fold; here it was always
    // a tooltip, because this page is a short list of rows somebody sets a
    // number in, so a paragraph under each would be most of the page.
    const hint = kit.tip(setting.description, Infinity);
    // TWO CONTROLS, BY TYPE. It was one — a `number` input — until
    // `oauth2.revokeRefreshOnLogout` joined this page on 2026-08-27, and a bool
    // gets the `select` of true/false that /admin/config's configRow() draws
    // rather than a checkbox: an unticked checkbox posts NOTHING, and this form
    // would read that as "the field was not sent" rather than as false.
    //
    // The bounds on the number input come off the setting itself, so the
    // browser's own refusal and the server's are the same three numbers. The
    // server still checks: an input attribute is a convenience for a person and
    // no constraint at all on a JSON body or a curl.
    const control = setting.type === 'bool'
      ? '<select name="' + kit.esc(setting.key) + '" id="' + kit.esc(id) +
        '"' + hint +
        '>' +
        ['true', 'false'].map(function (option) {
          return '<option value="' + option + '"' +
            (option === setting.text ? ' selected' : '') + '>' + option +
                 '</option>';
        }).join('') + '</select>'
      : '<input type="number" name="' + kit.esc(setting.key) + '" id="' +
        kit.esc(id) +
        '"' +
        hint + ' value="' + kit.esc(setting.text) + '"' +
        (typeof setting.min === 'number' ? ' min="' + setting.min + '"' : '') +
        (typeof setting.max === 'number' ? ' max="' + setting.max + '"' : '') +
        (typeof setting.step === 'number' ? ' step="' + setting.step + '"' :
         '') +
        ' size="10">';
    // WHICH ATTRIBUTE A CLIENT OVERRIDES THIS WITH, or a plain no. Read from
    // applications.js's own table rather than listed here, so a setting that
    // becomes per-client cannot reach this page without this column saying so.
    const override = snapshot.overridable.filter(function (row) {
      return row.setting === setting.key;
    })[0];
    const per = override
      ? '<code>' + kit.esc(override.attribute) + '</code>'
      : '<span class="state-none">' +
        t.html('consoleTokenLifetimes.notPerClient') + '</span>';
    return '<tr>' +
      '<td><label for="' + kit.esc(id) + '"' + hint + '>' +
      kit.esc(setting.label) +
      '</label><div ' +
      'class="note"><code>' + kit.esc(setting.key) + '</code>' +
      (setting.env ? ', <code>' + kit.esc(setting.env) + '</code>' : '') +
      '</div></td><td>' + control + '</td><td>' +
      kit.esc(setting.type === 'bool' ? '' :
               kit.humanSeconds(setting.value)) +
      '</td><td>' + per + '</td><td>' + (setting.overridden
        ? '<strong>' + kit.esc(SettingsForms.sourceNote(setting,
          snapshot.context || {}, t)) + '</strong>'
        : kit.esc(SettingsForms.sourceNote(setting, snapshot.context || {},
                                            t))) +
          '</td>' +
      '<td>' + issued + '</td></tr>';
  }

  // The warnings themselves, from the three numbers (#446): a page drawn in
  // a browser hands in what its view says.
  /**
   * Draws the warnings for an access, refresh and skew in seconds.
   *
   * @param access - the access token's lifetime
   * @param refresh - the refresh token's lifetime
   * @param skew - the clock skew allowed
   * @param t - the page's translator (#539); `web_applications.ts` passes
   *   its own
   * @returns the warnings as HTML, or '' for none
   */
  static tokenLifetimeWarningsFor(access, refresh, skew, t) {
    const notes = [];
    if (access >= refresh) {
      notes.push(t.html('consoleTokenLifetimes.accessOutlives',
                        { access: kit.humanSeconds(access),
                          refresh: kit.humanSeconds(refresh) }));
    }
    if (skew >= access) {
      notes.push(t.html('consoleTokenLifetimes.skewOutlives',
                        { skew: kit.humanSeconds(skew),
                          access: kit.humanSeconds(access) }));
    }
    if (!notes.length) {
      return '';
    }
    return notes.map(function (note) { return kit.warn(note); }).join('');
  }
}

export = TokenLifetimesPage;
