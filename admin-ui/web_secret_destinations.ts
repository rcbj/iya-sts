// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_secret_destinations.ts
//
// ---------------------------------------------------------------------------
// DIRECTORY → SECRET DESTINATIONS, DRAWN FROM ITS VIEW ALONE (#221 P3,
// 2026-10-06).
//
// Draws the register of secret push destinations from the answer of
// `GET /admin-api/secret-destinations`: where this realm pushes a service
// account's rotated password, each destination with its location, whether it
// is usable and why not, an Edit fold, a Test push and a Remove; and a form
// to add one. Every form posts an action of `POST /admin-api/secret-
// destinations/{action}` (rule 7), which the static console resolves through
// the operation's `mirrors`.
//
// **IN DIRECTORY, BESIDE ATTRIBUTE SOURCES**, because a destination IS a
// directory entry — an application entry under `ou=applications` declared for
// the `secret-destination` family — and the question the page answers is
// "what does this realm's directory say about where passwords go". Rotation's
// status is Monitoring's (#221 P4).
//
// **THE WRITE CREDENTIAL IS A BOX THAT IS NEVER FILLED.** The view carries no
// credential, only `credentialSet`; the box is a password input, empty, and
// left empty on a change it keeps the one set.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// ---------------------------------------------------------------------------

import kit = require('./web_kit');

type Json = any;

const esc = kit.esc;

/**
 * The page's path.
 */
const PAGE = '/admin/secret-destinations';

/**
 * Draws Directory → Secret destinations from the answer of
 * `GET /admin-api/secret-destinations`.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class SecretDestinationsPage {
  /**
   * Draws the page's body from its view.
   *
   * @param view - the answer of the page's management API operation
   * @param ctx - the render context; `write` decides whether controls are
   *   drawn
   * @returns the body as HTML
   */
  static render(view: Json, ctx?: Json): string {
    return SecretDestinationsPage.body(view, ctx || kit.context());
  }

  // One text box. Its label and hint arrive translated (#539).
  static text(name: string, label: string, value: unknown,
              hint?: string): string {
    return '<label>' + esc(label) + ' <input type="text" name="' + name +
      '" value="' + esc(value == null ? '' : value) + '"' +
      (hint ? ' placeholder="' + esc(hint) + '"' : '') + '></label>';
  }

  // One select over a closed set. The options are the view's own values,
  // submitted as they are, so only the label is translated.
  static select(name: string, label: string, options: string[],
                value: string): string {
    return '<label>' + esc(label) + ' <select name="' + name + '">' +
      options.map(function (one) {
        return '<option' + (one === value ? ' selected' : '') + '>' +
               esc(one) + '</option>';
      }).join('') + '</select></label>';
  }

  // The fields of a destination's form, filled with `row` (empty for a new
  // one). The credential box is never filled. The example placeholders are
  // values (a region, a URL), not words, and are drawn as they were.
  static fields(t: Json, json: Json, row: Json): string {
    const at = (row && row.location) || {};
    const providers: string[] = (json.providers || []).slice();
    if (row && row.provider && providers.indexOf(row.provider) < 0) {
      providers.push(row.provider);
    }
    return '<div class="formrow">' +
      this.select('provider',
                  t.text('consoleSecretDestinations.fields.provider'),
                  providers, (row && row.provider) || providers[0] || '') +
      this.select('payload',
                  t.text('consoleSecretDestinations.fields.payload'),
                  json.payloads || [], (row && row.payload) || 'password') +
      this.text('region', t.text('consoleSecretDestinations.fields.region'),
                at.region, 'us-east-1') +
      this.text('project',
                t.text('consoleSecretDestinations.fields.project'),
                at.project, 'my-project') +
      '</div><div class="formrow">' +
      this.text('endpoint',
                t.text('consoleSecretDestinations.fields.endpoint'),
                at.endpoint, 'https://vault.example.com:8200') +
      this.text('mount', t.text('consoleSecretDestinations.fields.mount'),
                at.mount, 'secret') +
      this.text('field', t.text('consoleSecretDestinations.fields.field'),
                at.field, 'value') +
      (json.fileAllowed || (row && row.provider === 'file')
        ? this.text('directory',
                    t.text('consoleSecretDestinations.fields.directory'),
                    at.directory, '/run/sts-test-secrets')
        : '') +
      '</div><div class="formrow"><label>' +
      t.html('consoleSecretDestinations.fields.caCertificates') + ' ' +
      '<textarea name="caCertificates" rows="3" cols="64" ' +
      'placeholder="-----BEGIN CERTIFICATE-----">' +
      esc(at.caCertificates || '') + '</textarea></label></div>' +
      '<div class="formrow"><label>' +
      t.html('consoleSecretDestinations.fields.credential') + ' <input ' +
      'type="password" name="credential" autocomplete="off" value="" ' +
      'placeholder="' + esc(row && row.credentialSet
        ? t.text('consoleSecretDestinations.fields.credentialKept')
        : t.text('consoleSecretDestinations.fields.credentialRequired')) +
      '"></label></div>';
  }

  // One destination's row: what it is, where it writes, whether it can.
  static row(t: Json, json: Json, row: Json, ctx: Json): string {
    const at = row.location || {};
    const where = row.provider === 'aws'
      ? t.text('consoleSecretDestinations.row.region',
               { region: at.region || '?' })
      : row.provider === 'gcp'
        ? (at.project ? t.text('consoleSecretDestinations.row.project',
                               { project: at.project })
                      : t.text('consoleSecretDestinations.row.fullNames'))
      : row.provider === 'azure' ? at.endpoint
      : row.provider === 'vault'
        ? t.text('consoleSecretDestinations.row.vaultAt',
                 { endpoint: at.endpoint, mount: at.mount || 'secret' })
      : row.provider === 'file' ? at.directory : '';
    const form = function (action: string, extra: string, label: string,
                           danger?: boolean): string {
      return '<form method="post" action="' + PAGE + '" class="inline">' +
        '<input type="hidden" name="action" value="' + action + '">' +
        '<input type="hidden" name="id" value="' + esc(row.id) + '">' +
        extra + ' <button type="submit"' + (danger ? ' class="danger"' : '') +
        '>' + esc(label) + '</button></form>';
    };
    const shape = (json.credentialShapes || {})[row.provider] || '';
    return '<tr><td class="who">' + esc(row.name) + '<br><span class="sub">' +
      '<a href="/admin/applications?application=' +
      encodeURIComponent(row.identifier) + '">' + esc(row.identifier) +
      '</a></span></td><td><code>' + esc(row.provider || '?') + '</code>' +
      '<br><span class="sub">' + esc(where || '') + '</span></td><td>' +
      esc(row.payload) + (row.provider === 'vault' && row.payload ===
        'password' ? '<br><span class="sub">' +
        t.html('consoleSecretDestinations.row.field',
               { field: at.field || 'value' }) + '</span>' : '') +
      '</td><td>' +
      (row.credentialSet
        ? t.html('consoleSecretDestinations.row.credentialSet') +
          ' <span class="sub">' +
          t.html('consoleSecretDestinations.row.neverShown') + '</span>'
        : (row.provider === 'file'
          ? '<span class="state-none">' +
            t.html('consoleSecretDestinations.row.noneNeeded') + '</span>'
          : '<span class="state-revoked">' +
            t.html('consoleSecretDestinations.row.notSet') + '</span>')) +
      (shape && shape !== 'none' ? '<br><span class="sub">' + esc(shape) +
                                   '</span>' : '') + '</td><td>' +
      (row.usable ? t.html('consoleSecretDestinations.row.usable')
                  : '<span class="state-revoked">' +
                    t.html('consoleSecretDestinations.row.notUsable') +
                    '</span>' +
                    row.problems.map(function (p: string) {
                      return '<div class="sub">' + esc(p) + '</div>';
                    }).join('')) + '</td><td class="act">' +
      (ctx.write
        ? form('test-push', '<input type="text" name="secretName" ' +
               'size="16" placeholder="' +
               esc(t.text('consoleSecretDestinations.row.testSecret')) +
               '" required>',
               t.text('consoleSecretDestinations.row.testPush')) +
          '<details><summary>' +
          t.html('consoleSecretDestinations.row.edit') +
          '</summary><form method="post" action="' +
          PAGE + '"><input type="hidden" name="action" ' +
          'value="update-destination"><input type="hidden" name="id" ' +
          'value="' + esc(row.id) + '"><div class="formrow">' +
          this.text('name', t.text('consoleSecretDestinations.row.name'),
                    row.name) + '</div>' +
          this.fields(t, json, row) + '<button type="submit">' +
          t.html('consoleSecretDestinations.row.save') + '</button>' +
          '</form></details>' +
          form('remove-destination', '',
               t.text('consoleSecretDestinations.row.remove'), true)
        : '') + '</td></tr>';
  }

  /**
   * Draws the page body.
   *
   * @param json - the view `GET /admin-api/secret-destinations` answers
   * @param ctx - the render context
   * @returns the HTML
   */
  static body(json: Json, ctx?: Json): string {
    const c = ctx || kit.context();
    // The page's words are its translator's (#539 phase 6).
    const t = c.t;
    const rows = (json.destinations || []).map((row: Json) =>
      this.row(t, json, row, c)).join('');
    return kit.note(t.html('consoleSecretDestinations.body.lead')) +
      (json.fileAllowed
        ? kit.warn(t.html('consoleSecretDestinations.body.development'))
        : '') +
      '<h3 id="destinations">' +
      t.html('consoleSecretDestinations.body.destinations') +
      '</h3><table><thead><tr>' +
      '<th>' + t.html('consoleSecretDestinations.body.thDestination') +
      '</th><th>' + t.html('consoleSecretDestinations.body.thProvider') +
      '</th><th>' + t.html('consoleSecretDestinations.body.thPayload') +
      '</th><th>' + t.html('consoleSecretDestinations.body.thCredential') +
      '</th><th>' + t.html('consoleSecretDestinations.body.thState') +
      '</th><th></th></tr></thead>' +
      '<tbody>' +
      (rows || '<tr><td colspan="6"><span class="state-none">' +
               t.html('consoleSecretDestinations.body.none') +
               '</span></td></tr>') +
      '</tbody></table>' +
      '<p class="sub">' + t.html('consoleSecretDestinations.body.testPush') +
      '</p>' +
      (c.write
        ? '<h3 id="add">' + t.html('consoleSecretDestinations.body.add') +
          '</h3><form method="post" ' +
          'action="' + PAGE + '"><input type="hidden" name="action" ' +
          'value="add-destination"><div class="formrow">' +
          this.text('identifier',
                    t.text('consoleSecretDestinations.body.identifier'), '',
                    'vault-prod') +
          this.text('name', t.text('consoleSecretDestinations.row.name'), '',
                    'Production Vault') + '</div>' +
          this.fields(t, json, null) + '<button type="submit">' +
          t.html('consoleSecretDestinations.body.addButton') + '</button>' +
          '</form>'
        : '') +
      '<p class="links"><code>GET /admin-api/secret-destinations</code></p>';
  }
}

export = SecretDestinationsPage;
