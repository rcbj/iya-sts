// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_sign_in_appearance.ts
//
// ---------------------------------------------------------------------------
// SERVER CONFIGURATION → SIGN-IN APPEARANCE (#717), DRAWN FROM ITS VIEW ALONE.
//
// `GET /admin-api/branding` answers everything drawn here, in the ambient
// realm; `common/branding.ts` is what it describes. Four tabs, in the order
// a reader asks:
//
//   * COLOURS — the four colours, each an `<input type="color">` with its hex
//     beside it, the tones derived from them, and the contrast of the text,
//     the links and the button text against WCAG 2.2 AA (4.5:1). One Save,
//     `action=save`, the four colours judged together (D3 refuses below AA).
//   * LAYOUT AND LOGO — the layout (a closed set), the display name, the
//     logo's alternative text and link, saved together; then the stored
//     logo, an upload (`action=logo`, a multipart form the runtime sends as
//     the operation takes it: the FILE as the body, `alt` as a query
//     parameter — `web_runtime.ts`'s `multipartBody()`), and a removal.
//   * PREVIEW (D5) — a GET form to the realm's `/web/branding/preview` with
//     `target="_blank"`. It is not a console path, so the runtime leaves it
//     to the browser, which opens the preview in a new tab with the values
//     in the form: pending values, seen before anything is saved.
//   * SETTINGS — the `Sign-in appearance` group's block, as every page
//     `SETTING_HOMES` names draws it. It is a second door onto the same
//     settings, and the only one onto `branding.logoMaxBytes` (the
//     process's) and onto a realm override's Reset.
//
// A SWATCH IS A DISABLED COLOUR INPUT. The console is sent with no inline
// style, so a derived tone cannot be painted with `style=""`; a disabled
// `<input type="color">` shows its colour and can be changed by nobody.
//
// A `web_` MODULE: other `web_` modules only, no log, bundled for a
// browser by `build-typescript.sh`.
// ---------------------------------------------------------------------------

import kit = require('./web_kit');
import SettingsForms = require('./web_settings');

type Json = any;

const esc = kit.esc;
const PAGE = '/admin/sign-in-appearance';

// The colours a realm sets: the view's member, the setting, the preview's
// query parameter.
const COLOURS = [
  { name: 'accent', key: 'branding.accentColor' },
  { name: 'page', key: 'branding.pageColor' },
  { name: 'card', key: 'branding.cardColor' },
  { name: 'text', key: 'branding.textColor' }
];

// The derived tones, in the view's `derived` member.
const DERIVED = ['onAccent', 'muted', 'faint', 'dim', 'border', 'rule'];

// The three contrasts the view reports, in its `contrast` member.
const CONTRASTS = ['text', 'accent', 'buttonText'];

/**
 * Draws Server configuration → Sign-in appearance from its management API
 * answer.
 */
class SignInAppearancePage {
  static readonly PAGE = PAGE;

  /**
   * Draws the page body.
   *
   * @param view - `GET /admin-api/branding`
   * @param ctx - the render context
   * @returns the body as HTML
   */
  static render(view: Json, ctx?: Json): string {
    return SignInAppearancePage.body(view || {}, ctx || kit.context());
  }

  /**
   * A six-digit colour, or the fallback where the view has none: an
   * `<input type="color">` takes nothing else.
   *
   * @param value - the colour
   * @param fallback - what to show instead
   * @returns `#rrggbb`
   */
  static hex(value: unknown, fallback: string): string {
    const text = String(value == null ? '' : value).toLowerCase();
    return /^#[0-9a-f]{6}$/.test(text) ? text : fallback;
  }

  /**
   * One colour's row in a form.
   *
   * @param t - the translator
   * @param id - the input's id
   * @param name - the field's name
   * @param label - the label's message key
   * @param hint - the hint's message key, or ''
   * @param value - the colour
   * @param off - ' disabled', or ''
   * @returns the row
   */
  static colourRow(t: Json, id: string, name: string, label: string,
                   hint: string, value: string, off: string): string {
    return '<div class="formrow"><label for="' + esc(id) + '">' +
      t.html(label) + '</label> <input type="color" id="' + esc(id) +
      '" name="' + esc(name) + '" value="' + esc(value) + '"' + off +
      '> <code>' + esc(value) + '</code>' +
      (hint ? ' <span class="hint">' + t.html(hint) + '</span>' : '') +
      '</div>';
  }

  /**
   * A swatch: a disabled colour input, labelled by its own name.
   *
   * @param value - the colour
   * @param label - what it is, for a screen reader
   * @returns the swatch
   */
  static swatch(value: string, label: string): string {
    return '<input type="color" value="' + esc(value) + '" disabled ' +
      'aria-label="' + esc(label) + '" title="' + esc(label) + '">';
  }

  /**
   * The Colours tab.
   *
   * @param t - the translator
   * @param v - the view
   * @param off - ' disabled', or ''
   * @returns the tab
   */
  static colours(t: Json, v: Json, off: string): string {
    const key = 'consoleSignInAppearance.';
    const colours = v.colours || {};
    const derived = v.derived || {};
    const contrast = v.contrast || {};
    const required = Number(contrast.required) || 4.5;
    const rows = COLOURS.map(function (one) {
      return SignInAppearancePage.colourRow(t, 'sia-' + one.name, one.key,
        key + 'colour.' + one.name, key + 'colour.' + one.name + 'Hint',
        SignInAppearancePage.hex(colours[one.name], '#000000'), off);
    }).join('');
    const tones = DERIVED.map(function (name) {
      const value = SignInAppearancePage.hex(derived[name], '#000000');
      const label = t.text(key + 'derived.' + name);
      return '<tr><td>' + esc(label) + '</td><td>' +
        SignInAppearancePage.swatch(value, label) + ' <code>' + esc(value) +
        '</code></td></tr>';
    }).join('');
    const checks = CONTRASTS.map(function (name) {
      const ratio = Number(contrast[name]);
      const passes = ratio >= required;
      return '<tr><td>' + t.html(key + 'contrast.' + name) + '</td><td>' +
        esc(isFinite(ratio) ? ratio.toFixed(2) + ':1' : '') + '</td><td>' +
        '<span class="' + (passes ? 'state-valid' : 'state-invalid') + '">' +
        t.html(key + (passes ? 'contrast.pass' : 'contrast.fail')) +
        '</span></td></tr>';
    }).join('');
    return '<h2 id="colours" data-tab="colours">' +
      t.html(key + 'colours.heading') + '</h2>' +
      kit.note(t.html(key + 'colours.lead')) +
      '<form method="post" action="' + PAGE + '" id="sia-colours">' +
      '<input type="hidden" name="action" value="save">' + rows +
      '<div class="formrow"><button type="submit"' + off + '>' +
      t.html(key + 'colours.save') + '</button></div></form>' +
      '<h3>' + t.html(key + 'contrast.heading') + '</h3>' +
      '<table><thead><tr><th>' + t.html(key + 'contrast.thPair') +
      '</th><th>' + t.html(key + 'contrast.thRatio') + '</th><th>' +
      t.html(key + 'contrast.thVerdict') + '</th></tr></thead><tbody>' +
      checks + '</tbody></table>' +
      '<h3>' + t.html(key + 'derived.heading') + '</h3>' +
      kit.note(t.html(key + 'derived.lead')) +
      '<table><thead><tr><th>' + t.html(key + 'derived.thName') +
      '</th><th>' + t.html(key + 'derived.thColour') + '</th></tr>' +
      '</thead><tbody>' + tones + '</tbody></table>';
  }

  /**
   * One text field with its hint.
   *
   * @param t - the translator
   * @param id - the input's id
   * @param name - the field's name
   * @param type - `text` or `url`
   * @param max - its longest value
   * @param label - the label's message key
   * @param hint - the hint's message key
   * @param value - its value
   * @param off - ' disabled', or ''
   * @returns the row
   */
  static textRow(t: Json, id: string, name: string, type: string,
                 max: number, label: string, hint: string, value: unknown,
                 off: string): string {
    return '<div class="formrow"><label for="' + esc(id) + '">' +
      t.html(label) + '</label> <input type="' + type + '" id="' +
      esc(id) + '" name="' + esc(name) + '" maxlength="' + max +
      '" size="48" value="' + esc(value == null ? '' : value) + '"' + off +
      '> <span class="hint">' + t.html(hint) + '</span></div>';
  }

  /**
   * The stored logo, drawn at 64 pixels high with its facts, or a sentence
   * saying there is none.
   *
   * @param t - the translator
   * @param v - the view
   * @returns the markup
   */
  static storedLogo(t: Json, v: Json): string {
    const key = 'consoleSignInAppearance.';
    const logo = v.logo;
    if (!logo) {
      return '<p><span class="state-none">' + t.html(key + 'logo.none') +
        '</span></p>';
    }
    const width = Number(logo.width) || 0;
    const height = Number(logo.height) || 0;
    // Drawn 64 pixels high, its width in proportion: attributes, not a
    // style, which the console's policy would refuse.
    const shownHeight = Math.min(64, height || 64);
    const shownWidth = height ? Math.max(1, Math.round(width * shownHeight /
                                                       height)) : 64;
    const when = String(logo.updatedAt || '');
    return '<p><img class="sia-logo" id="sia-logo" src="' +
      esc(logo.src || logo.url || '') + '" alt="' + esc(v.logoAlt || '') +
      '" width="' + shownWidth + '" height="' + shownHeight + '"></p>' +
      '<ul><li>' + t.html(key + 'logo.facts', {
        type: String(logo.type || ''), width: width, height: height,
        bytes: Number(logo.bytes) || 0 }) + '</li>' +
      '<li>' + t.html(key + 'logo.digest') + ' <code>' +
      esc(String(logo.sha256 || '').slice(0, 16)) + '</code></li>' +
      '<li>' + (logo.updatedBy
        ? t.html(key + 'logo.updated', { when: when,
                                         who: String(logo.updatedBy) })
        : t.html(key + 'logo.updatedNobody', { when: when })) +
      '</li></ul>';
  }

  /**
   * The Layout and logo tab.
   *
   * @param t - the translator
   * @param v - the view
   * @param off - ' disabled', or ''
   * @returns the tab
   */
  static layoutAndLogo(t: Json, v: Json, off: string): string {
    const key = 'consoleSignInAppearance.';
    const layouts = Array.isArray(v.layouts) && v.layouts.length
      ? v.layouts : ['centered', 'split', 'banner'];
    const choices = layouts.map(function (name: string) {
      const id = 'sia-layout-' + name;
      return '<div class="formrow"><label for="' + esc(id) + '"><input ' +
        'type="radio" id="' + esc(id) + '" name="branding.layout" value="' +
        esc(name) + '"' + (name === v.layout ? ' checked' : '') + off +
        '> ' + t.html(key + 'layout.' + name) + '</label></div>';
    }).join('');
    const max = Number(v.logoMaxBytes) || 0;
    const remove = v.logo
      ? '<form method="post" action="' + PAGE + '" id="sia-remove-logo">' +
        '<input type="hidden" name="action" value="remove-logo">' +
        '<button type="submit" class="danger"' + off + '>' +
        t.html(key + 'logo.remove') + '</button></form>'
      : '';
    return '<h2 id="layout" data-tab="layout">' +
      t.html(key + 'layout.heading') + '</h2>' +
      '<form method="post" action="' + PAGE + '" id="sia-layout">' +
      '<input type="hidden" name="action" value="save">' +
      '<fieldset><legend>' + t.html(key + 'layout.legend') + '</legend>' +
      choices + '</fieldset>' +
      SignInAppearancePage.textRow(t, 'sia-display-name',
        'branding.displayName', 'text', 80, key + 'layout.displayName',
        key + 'layout.displayNameHint', v.displayName, off) +
      SignInAppearancePage.textRow(t, 'sia-logo-alt', 'branding.logoAlt',
        'text', 160, key + 'layout.logoAlt', key + 'layout.logoAltHint',
        v.logoAlt, off) +
      SignInAppearancePage.textRow(t, 'sia-logo-link',
        'branding.logoLinkUrl', 'url', 2048, key + 'layout.logoLink',
        key + 'layout.logoLinkHint', v.logoLinkUrl, off) +
      '<div class="formrow"><button type="submit"' + off + '>' +
      t.html(key + 'layout.save') + '</button></div></form>' +
      '<h3>' + t.html(key + 'logo.heading') + '</h3>' +
      SignInAppearancePage.storedLogo(t, v) +
      '<form method="post" action="' + PAGE + '" id="sia-upload" ' +
      'enctype="multipart/form-data">' +
      '<input type="hidden" name="action" value="logo">' +
      '<div class="formrow"><label for="sia-logo-file">' +
      t.html(key + 'logo.file') + '</label> <input type="file" ' +
      'id="sia-logo-file" name="file" accept="image/png,image/jpeg,' +
      'image/webp" required' + off + '> <span class="hint">' +
      t.html(key + 'logo.fileHint', { max: max }) + '</span></div>' +
      SignInAppearancePage.textRow(t, 'sia-upload-alt', 'alt', 'text', 160,
        key + 'logo.alt', key + 'layout.logoAltHint', v.logoAlt, off) +
      '<div class="formrow"><button type="submit"' + off + '>' +
      t.html(key + 'logo.upload') + '</button></div></form>' + remove;
  }

  /**
   * The Preview tab: a GET form to the realm's preview, opened in a new
   * tab by the browser, never by the runtime.
   *
   * @param t - the translator
   * @param v - the view
   * @returns the tab
   */
  static preview(t: Json, v: Json): string {
    const key = 'consoleSignInAppearance.';
    const colours = v.colours || {};
    const layouts = Array.isArray(v.layouts) && v.layouts.length
      ? v.layouts : ['centered', 'split', 'banner'];
    const target = String(v.previewUrl || v.preview ||
                          '/web/branding/preview');
    const rows = COLOURS.map(function (one) {
      return SignInAppearancePage.colourRow(t, 'sia-pv-' + one.name,
        one.name, key + 'colour.' + one.name, '',
        SignInAppearancePage.hex(colours[one.name], '#000000'), '');
    }).join('');
    return '<h2 id="preview" data-tab="preview">' +
      t.html(key + 'preview.heading') + '</h2>' +
      kit.note(t.html(key + 'preview.lead')) +
      '<form method="get" action="' + esc(target) + '" target="_blank" ' +
      'id="sia-preview">' + rows +
      '<div class="formrow"><label for="sia-pv-layout">' +
      t.html(key + 'preview.layout') + '</label> <select id="sia-pv-layout" ' +
      'name="layout">' + layouts.map(function (name: string) {
        return '<option value="' + esc(name) + '"' +
          (name === v.layout ? ' selected' : '') + '>' + esc(name) +
          '</option>';
      }).join('') + '</select></div>' +
      '<div class="formrow"><button type="submit">' +
      t.html(key + 'preview.open') + '</button></div></form>';
  }

  /**
   * Draws the page.
   *
   * @param json - the view
   * @param ctx - the render context
   * @returns the HTML
   */
  static body(json: Json, ctx?: Json): string {
    const c = ctx || kit.context();
    const t = c.t;
    const key = 'consoleSignInAppearance.';
    const off = c.write ? '' : ' disabled';
    return kit.note(t.html(key + 'lead', { realm: String(json.realm ||
                                                         'default') })) +
      kit.note(t.html(key + (json.customised ? 'customised.yes'
                                             : 'customised.no'))) +
      (c.write ? '' : kit.note(t.html(key + 'readOnly'))) +
      SignInAppearancePage.colours(t, json, off) +
      SignInAppearancePage.layoutAndLogo(t, json, off) +
      SignInAppearancePage.preview(t, json) +
      SettingsForms.forms(json.settings || { groups: [] }, PAGE,
                          undefined, t) +
      '<p class="links" data-metadata><code>GET /admin-api/branding' +
      '</code></p>';
  }
}

export = SignInAppearancePage;
