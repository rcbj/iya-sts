// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_saml_assertions.ts
//
// ---------------------------------------------------------------------------
// PROTOCOLS → SAML ASSERTIONS, DRAWN FROM ITS VIEW ALONE (#446, 2026-10-05).
//
// Draws SAML assertions from the answer of `GET /admin-api/saml-assertions`:
// how long an assertion issued here is valid for, the clock skew, signing and
// encryption per profile, and what was issued.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// It was drawn inside the route of `/admin/saml-assertions` in
// `admin-ui/admin.ts`, which still draws the page until the console's cutover
// by calling this with its view passed through JSON.
// ---------------------------------------------------------------------------

import kit = require('./web_kit');
import SettingsForms = require('./web_settings');

type Json = any;

/**
 * Draws SAML assertions from the answer of `GET /admin-api/saml-assertions`:
 * how long an assertion issued here is valid for, the clock skew, signing and
 * encryption per profile, and what was issued.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class SamlAssertionsPage {
  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static body(ctx, json) {
    // The page's words are its translator's (#539 phase 6); a setting's own
    // description and label come from the view and are drawn as they come.
    // A link carries an href, which a message may not, so a sentence around
    // one is split into messages with the anchor in the code.
    const t = ctx.t;
    const settings = json.settings;
    const snapshot = { assertions: { byKind: json.assertionsIssued.byKind },
                       rows: json.rows, seconds: json.seconds,
                       context: json.context };
    const anyOverridden =
        settings.some(function (setting) { return setting.overridden; });

    const inner = kit.note(t.html('consoleSamlAssertions.leadBefore') +
      '<a href="/admin/config">' +
      t.html('consoleSamlAssertions.leadConfig') + '</a>' +
      t.html('consoleSamlAssertions.leadMiddle') +
      '<a href="/admin/saml2">SAML 2.0</a>' +
      t.html('consoleSamlAssertions.leadAnd') +
      '<a href="/admin/saml11">SAML 1.1</a>' +
      t.html('consoleSamlAssertions.leadAfter')) +

      kit.warn(t.html('consoleSamlAssertions.nextOnly') + ' ' +
      SettingsForms.durability(json.context, t)) +

      SamlAssertionsPage.samlAssertionWarnings(t, json) +

      '<h2>' + t.html('consoleSamlAssertions.hSixteen') + '</h2>' +
      kit.note(t.html('consoleSamlAssertions.defaultsBefore') +
      '<a href="/admin/applications">' +
      t.html('consoleSamlAssertions.defaultsLink') + '</a>' +
      t.html('consoleSamlAssertions.defaultsAfter')) +
      kit.note(t.html('consoleSamlAssertions.units')) +
      '<form method="post" action="/admin/saml-assertions">' +
      '<input type="hidden" name="action" value="set">' +
      ['saml2', 'saml11', 'wsfed', ''].map(function (profile) {
        const mine = settings.filter(function (setting) {
          const row = json.rows.filter(function (one) {
            return one.key === setting.key;
          })[0];
          return row && row.profile === profile;
        });
        if (!mine.length) return '';
        // The heading is the profile's own name, and the empty profile is the
        // skew — which is headed by what it IS rather than by a profile it
        // does not belong to, because putting it under either would be the
        // claim this page spends a section denying.
        const heading = profile === 'saml2' ? 'SAML 2.0'
                      : (profile === 'saml11' ? 'SAML 1.1'
                      : (profile === 'wsfed' ? 'WS-Federation' :
                         t.text('consoleSamlAssertions.everyProfile')));
        return '<h3>' + kit.esc(heading) + '</h3>' +
          '<table><tr><th>' + t.html('consoleSamlAssertions.thSetting') +
          '</th><th>' + t.html('consoleSamlAssertions.thValue') +
          '</th><th>' + t.html('consoleSamlAssertions.thWhichIs') + '</th>' +
          '<th>' + t.html('consoleSamlAssertions.thPerApplication') +
          '</th><th>' + t.html('consoleSamlAssertions.thSource') + '</th>' +
          '<th>' + t.html('consoleSamlAssertions.thHeld') + '</th></tr>' +
          mine.map(function (setting) {
            return SamlAssertionsPage.samlAssertionSettingRow(t, setting,
              snapshot);
          }).join('') +
          '</table>';
      }).join('') +
      '<p><button>' + t.html('consoleSamlAssertions.save') +
      '</button></p>' +
      kit.note(t.html('consoleSamlAssertions.allChecked')) +
      '</form>' +

      (anyOverridden
        ? '<div class="ok">' +
          t.html('consoleSamlAssertions.overriddenCount', {
            n: String(settings.filter(function (s) {
              return s.overridden;
            }).length),
            kept: SettingsForms.overrideKept(json.context, undefined, t) }) +
          ' <form ' +
          'method="post" action="/admin/saml-assertions" ' +
          'class="inline"><input type="hidden" name="action" ' +
          'value="defaults"><button class="secondary">' +
          t.html('consoleSamlAssertions.putBack') + '</button></form> ' +
          t.html('consoleSamlAssertions.putBackNote') + '<a ' +
          'href="/admin/config">' +
          t.html('consoleSamlAssertions.configuration') + '</a>' +
          t.html('consoleSamlAssertions.resetAll') + '</div>'
        : kit.note(t.html('consoleSamlAssertions.noneOverridden', {
            file: (json.context || {}).configFile ||
              t.text('consoleSamlAssertions.theAppconfigFile'),
            defaults: (json.context || {}).defaultsFile }))) +

      '<h2>' + t.html('consoleSamlAssertions.hSkew') + '</h2>' +
      kit.note(t.html('consoleSamlAssertions.skewBothEnds')) +
      '<table><tr><th>' + t.html('consoleSamlAssertions.thProfile') +
      '</th><th>NotBefore</th><th>NotOnOrAfter</th>' +
      '<th class="num">' + t.html('consoleSamlAssertions.thStatedWindow') +
      '</th></tr>' +
      json.rows.filter(function (row) { return row.kind; })
                             .map(function (row) {
        const skew = json.seconds['saml.clockSkewS'];
        const lifetime = json.seconds[row.key];
        return '<tr><td>' + kit.esc(row.kind) + '</td>' +
          '<td><code>now' +
          (skew ? ' &minus; ' + kit.esc(String(skew)) + 's' : '') +
          '</code></td><td><code>now ' +
          '+ ' + kit.esc(kit.humanSeconds(lifetime)) +
            (skew ? ' + ' + kit.esc(String(skew)) + 's' : '') +
            '</code></td>' +
          '<td class="num">' +
          kit.esc(kit.humanSeconds(lifetime + 2 * skew)) +
          '</td></tr>';
      }).join('') +
      '</table><h2>' + t.html('consoleSamlAssertions.hFour') + '</h2>' +
      kit.note(t.html('consoleSamlAssertions.four')) +
      // The path's `{id}` is a parameter, because a message's braces are
      // its placeholders.
      kit.note(t.html('consoleSamlAssertions.notOauthBefore',
                      { path: '/federation/acs/{id}' }) +
      '<a href="/admin/token-lifetimes">' +
      t.html('consoleSamlAssertions.notOauthLink') + '</a>' +
      t.html('consoleSamlAssertions.notOauthAfter')) +

      '<h2>' + t.html('consoleSamlAssertions.hOutThere') + '</h2>' +
      kit.note(t.html('consoleSamlAssertions.outThere', {
        held: String(json.assertionsIssued.held),
        cap: String(json.assertionsIssued.cap),
        forgotten: String(json.assertionsIssued.forgotten) }) + '<a ' +
      'href="/admin/tokens">' +
      t.html('consoleSamlAssertions.tokensLink') + '</a>' +
      t.html('consoleSamlAssertions.outThereAfter')) +
      '<table><tr><th>' + t.html('consoleSamlAssertions.thProfile') +
      '</th><th class="num">' + t.html('consoleSamlAssertions.thIssued') +
      '</th><th ' +
      'class="num">' + t.html('consoleSamlAssertions.thValid') +
      '</th><th class="num">' + t.html('consoleSamlAssertions.thExpired') +
      '</th><th ' +
      'class="num">' + t.html('consoleSamlAssertions.thNoExpiry') +
      '</th></tr>' +
      (json.assertionsIssued.byKind.map(function (row) {
        return '<tr><td><code>' + kit.esc(row.kind) + '</code></td>' +
          '<td class="num">' + row.issued + '</td>' +
          '<td class="num state-valid">' + row.valid + '</td>' +
          '<td class="num state-expired">' + row.expired + '</td>' +
          '<td class="num state-none">' + row.noExpiry + '</td></tr>';
      }).join('')) +
      '</table>' +

      '<h2>' + t.html('consoleSamlAssertions.hTwoThings') + '</h2>' +
      kit.note(t.html('consoleSamlAssertions.twoThings')) +

      kit.note(t.html('consoleSamlAssertions.footer'));

    return inner;
  }

  // One row of the form. The same shape tokenLifetimeRow() draws and for the
  // same reasons — a `number` input with `min`, `max` and `step` off the
  // setting itself, so the browser's refusal and the server's are the same
  // three numbers — differing only in that the unit is per row here rather than
  // seconds throughout, and that what sits in the last column is a count of
  // assertions rather than of tokens.
  /**
   * Draws one row of the SAML assertion settings form: the control by type,
   * the value in words, the per-application attribute, its source, and how
   * many assertions of its kind are valid and expired.
   *
   * @param t - the page's translator (#539)
   * @param setting - the described setting
   * @param snapshot - the statistics snapshot the assertion counts come from
   * @returns the table row as HTML
   */
  static samlAssertionSettingRow(t, setting, snapshot) {
    const id = 'sa-' + setting.key.replace(/\./g, '-');
    const row = snapshot.rows.filter(function (one) {
      return one.key === setting.key;
    })[0];
    const counts = (row && row.kind)
      ? (snapshot.assertions.byKind.filter(function (
          k) { return k.kind === row.kind; })[0] || null)
      : null;
    const issued = counts
      ? '<span class="state-valid">' +
        t.html('consoleSamlAssertions.nValid', { n: counts.valid }) +
        '</span>, ' +
        '<span class="state-expired">' +
        t.html('consoleSamlAssertions.nExpired', { n: counts.expired }) +
        '</span>'
      : '<span class="state-none">&mdash;</span>';
    const hint = kit.tip(setting.description, Infinity);
    // THREE CONTROLS, BY TYPE, and they are the ones `/admin/config`'s
    // configRow() draws — a `select` of true/false for a bool rather than a
    // checkbox, because an unticked checkbox sends NOTHING and this form would
    // then read "sign no assertion" as "the field was not posted". That is the
    // same reason configRow() uses a select, and getting it wrong here would be
    // a silent one. THREE CONTROLS NOW, not two: `enum` joined bool and int
    // when the two encryption algorithm rows arrived. It draws the setting's
    // own enumValues, so a value added to that list in config.js appears here
    // without this file being touched — and a value REMOVED there stops being
    // offerable, which is what keeps the form from proposing something the
    // action would refuse.
    const control = setting.type === 'enum'
      ? '<select name="' + kit.esc(setting.key) + '" id="' + kit.esc(id) +
        '"' + hint +
        '>' +
        (setting.enumValues || []).map(function (option) {
          // An enum whose set holds the empty string (#86 made
          // `pki.signatureAlgorithm` one) draws it as what it means rather
          // than as a blank line.
          return '<option value="' + kit.esc(option) + '"' +
            (option === setting.text ? ' selected' : '') + '>' +
            kit.esc(option === ''
              ? t.text('consoleSamlAssertions.emptyDefault') : option) +
                 '</option>';
        }).join('') + '</select>'
      : (setting.type === 'bool'
      ? '<select name="' + kit.esc(setting.key) + '" id="' + kit.esc(id) +
        '"' + hint +
        '>' +
        ['true', 'false'].map(function (option) {
          return '<option value="' + option + '"' +
            (option === setting.text ? ' selected' : '') + '>' + option +
                 '</option>';
        }).join('') + '</select>'
      : (setting.type === 'int'
        ? '<input type="number" name="' + kit.esc(setting.key) + '" id="' +
          kit.esc(id) +
          '"' +
          hint + ' value="' + kit.esc(setting.text) + '"' +
          (typeof setting.min === 'number' ? ' min="' + setting.min + '"' :
           '') +
          (typeof setting.max === 'number' ? ' max="' + setting.max + '"' :
           '') +
          (typeof setting.step === 'number' ? ' step="' + setting.step + '"' :
           '') +
          ' size="10"> ' + kit.esc(row ? row.unit : '')
        : '<input type="text" name="' + kit.esc(setting.key) + '" id="' +
          kit.esc(id) +
          '"' +
          hint + ' size="40" value="' + kit.esc(setting.text) + '">'));
    // What an application would override this with. Named rather than
    // described, because the whole point of the column is that somebody reading
    // this page can go and type the exception on an application entry — and the
    // attribute name is what they have to type.
    const per = (row && row.field)
      ? '<code>' + kit.esc(row.field) + '</code>'
      : '<span class="state-none">' +
        t.html('consoleSamlAssertions.notPerApplication') + '</span>';
    return '<tr>' +
      '<td><label for="' + kit.esc(id) + '"' + hint + '>' +
      kit.esc(setting.label) +
      '</label><div ' +
      'class="note"><code>' + kit.esc(setting.key) + '</code>' +
      (setting.env ? ', <code>' + kit.esc(setting.env) + '</code>' : '') +
      '</div></td><td>' + control + '</td><td>' +
      kit.esc(setting.type === 'int' && row && row.unit
        ? kit.humanSeconds(snapshot.seconds[setting.key])
        : '') + '</td>' +
      '<td>' + per + '</td>' +
      '<td>' + (setting.overridden
        ? '<strong>' + kit.esc(SettingsForms.sourceNote(setting,
          snapshot.context || {}, t)) + '</strong>'
        : kit.esc(SettingsForms.sourceNote(setting,
          snapshot.context || {}, t))) + '</td>' +
      '<td>' + issued + '</td></tr>';
  }

  // The states these settings can legally be in that are worth being told
  // about. Nothing here is refused — this service exists to be pointed at a
  // relying party and made to misbehave on purpose — but a page that showed
  // three numbers and not their consequence would leave the consequence to be
  // found from a relying party that stopped working.
  /**
   * Draws a warning for each legal but surprising state of the SAML
   * assertion settings: a clock skew at least as long as an assertion's
   * lifetime, or a skew of zero.
   *
   * @param t - the page's translator (#539)
   * @param json - the page's view (`rows`, `seconds`)
   * @returns the warnings as HTML, or an empty string
   */
  static samlAssertionWarnings(t, json) {
    const skew = json.seconds['saml.clockSkewS'];
    const notes = [];
    json.rows.filter(function (row) { return row.kind; })
                           .forEach(function (row) {
      const lifetime = json.seconds[row.key];
      if (skew > 0 && skew >= lifetime) {
        notes.push(t.html('consoleSamlAssertions.warnSkewLong', {
          kind: row.kind, skew: kit.humanSeconds(skew),
          lifetime: kit.humanSeconds(lifetime), key: row.key }));
      }
    });
    if (skew === 0) {
      notes.push(t.html('consoleSamlAssertions.warnSkewZero'));
    }
    if (!notes.length) {
      return '';
    }
    return notes.map(function (note) { return kit.warn(note); }).join('');
  }
}

export = SamlAssertionsPage;
