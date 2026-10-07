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

  // One text box.
  static text(name: string, label: string, value: unknown,
              hint?: string): string {
    return '<label>' + esc(label) + ' <input type="text" name="' + name +
      '" value="' + esc(value == null ? '' : value) + '"' +
      (hint ? ' placeholder="' + esc(hint) + '"' : '') + '></label>';
  }

  // One select over a closed set.
  static select(name: string, label: string, options: string[],
                value: string): string {
    return '<label>' + esc(label) + ' <select name="' + name + '">' +
      options.map(function (one) {
        return '<option' + (one === value ? ' selected' : '') + '>' +
               esc(one) + '</option>';
      }).join('') + '</select></label>';
  }

  // The fields of a destination's form, filled with `row` (empty for a new
  // one). The credential box is never filled.
  static fields(json: Json, row: Json): string {
    const at = (row && row.location) || {};
    const providers: string[] = (json.providers || []).slice();
    if (row && row.provider && providers.indexOf(row.provider) < 0) {
      providers.push(row.provider);
    }
    return '<div class="formrow">' +
      this.select('provider', 'Provider', providers,
                  (row && row.provider) || providers[0] || '') +
      this.select('payload', 'Payload', json.payloads || [],
                  (row && row.payload) || 'password') +
      this.text('region', 'Region (aws)', at.region, 'us-east-1') +
      this.text('project', 'Project (gcp)', at.project, 'my-project') +
      '</div><div class="formrow">' +
      this.text('endpoint', 'Vault URL (azure, vault)', at.endpoint,
                'https://vault.example.com:8200') +
      this.text('mount', 'KV mount (vault)', at.mount, 'secret') +
      this.text('field', 'Field (vault, password payload)', at.field,
                'value') +
      (json.fileAllowed || (row && row.provider === 'file')
        ? this.text('directory', 'Directory (file, development only)',
                    at.directory, '/run/sts-test-secrets')
        : '') +
      '</div><div class="formrow"><label>CA certificates (PEM, vault) ' +
      '<textarea name="caCertificates" rows="3" cols="64" ' +
      'placeholder="-----BEGIN CERTIFICATE-----">' +
      esc(at.caCertificates || '') + '</textarea></label></div>' +
      '<div class="formrow"><label>Write credential <input ' +
      'type="password" name="credential" autocomplete="off" value="" ' +
      'placeholder="' + esc(row && row.credentialSet
                              ? 'set — leave empty to keep it'
                              : 'required, except for a file') +
      '"></label></div>';
  }

  // One destination's row: what it is, where it writes, whether it can.
  static row(json: Json, row: Json, ctx: Json): string {
    const at = row.location || {};
    const where = row.provider === 'aws' ? 'region ' + (at.region || '?')
      : row.provider === 'gcp' ? (at.project ? 'project ' + at.project
                                             : 'full resource names')
      : row.provider === 'azure' ? at.endpoint
      : row.provider === 'vault' ? at.endpoint + ', mount ' +
                                   (at.mount || 'secret')
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
        'password' ? '<br><span class="sub">field ' +
        esc(at.field || 'value') + '</span>' : '') + '</td><td>' +
      (row.credentialSet
        ? 'set <span class="sub">(never shown)</span>'
        : (row.provider === 'file' ? '<span class="state-none">none ' +
                                     'needed</span>'
                                   : '<span class="state-revoked">not ' +
                                     'set</span>')) +
      (shape && shape !== 'none' ? '<br><span class="sub">' + esc(shape) +
                                   '</span>' : '') + '</td><td>' +
      (row.usable ? 'usable'
                  : '<span class="state-revoked">not usable</span>' +
                    row.problems.map(function (p: string) {
                      return '<div class="sub">' + esc(p) + '</div>';
                    }).join('')) + '</td><td class="act">' +
      (ctx.write
        ? form('test-push', '<input type="text" name="secretName" ' +
               'size="16" placeholder="a test secret" required>',
               'Test push') +
          '<details><summary>Edit</summary><form method="post" action="' +
          PAGE + '"><input type="hidden" name="action" ' +
          'value="update-destination"><input type="hidden" name="id" ' +
          'value="' + esc(row.id) + '"><div class="formrow">' +
          this.text('name', 'Name', row.name) + '</div>' +
          this.fields(json, row) + '<button type="submit">Save</button>' +
          '</form></details>' + form('remove-destination', '', 'Remove', true)
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
    const rows = (json.destinations || []).map((row: Json) =>
      this.row(json, row, c)).join('');
    return kit.note('Where this realm PUSHES a service account\'s rotated ' +
        'password: a secrets manager the new password is written to as a ' +
        'new version <strong>before</strong> its hash is committed here, so ' +
        'a failed push changes nothing. Each destination is an application ' +
        'entry declared for the <em>Secret push destination</em> family, ' +
        'holding its own write credential — sealed, and never shown again ' +
        'once set. <strong>A push never creates a secret</strong>: the ' +
        'secret must already exist, so the credential needs write on the ' +
        'named secrets and nothing more. A service account names a ' +
        'destination and a secret on its own page.') +
      (json.fileAllowed ? kit.warn('<strong>Development mode.</strong> A ' +
        '<code>file</code> destination is offered here and refused in ' +
        'product mode: a password written to this container\'s disk is not ' +
        'in a secrets manager.') : '') +
      '<h3 id="destinations">Destinations</h3><table><thead><tr>' +
      '<th>Destination</th><th>Provider</th><th>Payload</th>' +
      '<th>Write credential</th><th>State</th><th></th></tr></thead>' +
      '<tbody>' +
      (rows || '<tr><td colspan="6"><span class="state-none">No secret ' +
               'destination is registered in this realm.</span></td></tr>') +
      '</tbody></table>' +
      '<p class="sub">A <strong>test push</strong> writes a canary — a ' +
      'random password nobody uses — to a secret kept for testing; the ' +
      'secret a service account rotates into is refused.</p>' +
      (c.write
        ? '<h3 id="add">Add a destination</h3><form method="post" ' +
          'action="' + PAGE + '"><input type="hidden" name="action" ' +
          'value="add-destination"><div class="formrow">' +
          this.text('identifier', 'Identifier', '', 'vault-prod') +
          this.text('name', 'Name', '', 'Production Vault') + '</div>' +
          this.fields(json, null) + '<button type="submit">Add</button>' +
          '</form>'
        : '') +
      '<p class="links"><code>GET /admin-api/secret-destinations</code></p>';
  }
}

export = SecretDestinationsPage;
