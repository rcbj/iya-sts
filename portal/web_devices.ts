// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_devices.ts
//
// ---------------------------------------------------------------------------
// `/portal/devices`, DRAWN IN THE BROWSER (#568), from `GET
// /account-api/devices` (`portal_devices.ts`): the person's devices with a
// Remove button each; then either the armed link ceremony, or the key-proof
// step and the passkeys that can be linked; then "remember this browser".
//
// THE LINK CEREMONY is the markup the server-rendered page drew — `#wa-data`
// (`data-mode="get"`), a `#wa-go` button, `#wa-form` with a hidden
// `#wa-credential` — and the runtime runs it (`web_portal_webauthn.ts`). The
// form's own button is real: pressed without a ceremony it posts a
// `link-finish` with no assertion, answered by a sentence saying so.
//
// A `web_` MODULE: it requires other `web_` modules only and logs nothing.
// ---------------------------------------------------------------------------

import kit = require('./web_portal_kit');

type Json = any;
type PortalPage = import('../types/account-api').PortalPage;

const PATH = kit.BASE + '/devices';

/**
 * `/portal/devices`. A static utility class.
 */
class DevicesPages {
  /**
   * A form posting one action, with its hidden fields.
   *
   * @param action - the action
   * @param inner - the fields and buttons
   * @param id - the form's id, or ''
   * @returns the HTML
   */
  static form(action: string, inner: string, id?: string): string {
    return '<form method="post" action="' + PATH + '"' +
      (id ? ' id="' + id + '"' : '') + '>' +
      '<input type="hidden" name="action" value="' + action + '">' + inner +
      '</form>';
  }

  // The device choice and the descriptive fields, shared by both forms.
  /**
   * Which device, and what to call it.
   *
   * @param view - the page's view
   * @param t - the translator
   * @returns the HTML
   */
  static targetFields(view: Json, t: Json): string {
    return '<label for="dev-target">' +
      t.html('portalDevices.target.which') + '</label>' +
      '<select id="dev-target" name="device"><option value="">' +
      t.html('portalDevices.target.newDevice') + '</option>' +
      (view.devices || []).map(function (one: Json): string {
        return '<option value="' + kit.esc(one.id) + '">' +
          t.html('portalDevices.target.anotherKey', { name: one.label }) +
          '</option>';
      }).join('') + '</select>' +
      '<label for="dev-label">' + t.html('portalDevices.target.name') +
      '</label><input type="text" id="dev-label" name="label" ' +
      'maxlength="128" placeholder="' +
      kit.esc(t.text('portalDevices.target.namePlaceholder')) + '">' +
      // The platform names are data (`devices.PLATFORMS`), drawn as they are.
      '<label for="dev-platform">' + t.html('portalDevices.target.platform') +
      '</label><select id="dev-platform" name="platform"><option value="">' +
      '—</option>' + (view.platforms || []).map(function (p: string): string {
        return '<option value="' + kit.esc(p) + '">' + kit.esc(p) +
          '</option>';
      }).join('') + '</select>' +
      '<label for="dev-model">' + t.html('portalDevices.target.model') +
      '</label><input type="text" id="dev-model" name="model" ' +
      'maxlength="128"><label for="dev-os">' +
      t.html('portalDevices.target.os') + '</label>' +
      '<input type="text" id="dev-os" name="os" maxlength="128">';
  }

  // THE JWK PROOF block: the challenge form, or the proof form while one
  // is held.
  /**
   * The key-proof step.
   *
   * @param view - the page's view
   * @param t - the translator
   * @returns the HTML
   */
  static proofBlock(view: Json, t: Json): string {
    const pending = view.proof;
    if (!pending) {
      return '<h2>' + t.html('portalDevices.proof.heading') + '</h2>' +
        '<p class="sub">' + t.html('portalDevices.proof.intro') + '</p>' +
        DevicesPages.form('challenge', '<button type="submit">' +
          t.html('portalDevices.proof.getChallenge') + '</button>');
    }
    return '<h2>' + t.html('portalDevices.proof.heading') + '</h2>' +
      '<p class="sub">' + t.html('portalDevices.proof.answerBefore',
        { when: t.date(Number(pending.expiresAt)) }) + '</p>' +
      '<table><tr><th>' + t.html('portalDevices.proof.challenge') +
      '</th><td><code id="dev-challenge">' + kit.esc(pending.challenge) +
      '</code></td></tr><tr><th>' + t.html('portalDevices.proof.audience') +
      '</th><td><code id="dev-audience">' + kit.esc(view.audience) +
      '</code></td></tr><tr><th>' + t.html('portalDevices.proof.header') +
      '</th><td><code>' + kit.esc(view.proofTyp) + '</code>' +
      t.html('portalDevices.proof.headerKey') + '</td></tr></table>' +
      DevicesPages.form('prove',
        '<input type="hidden" name="challenge" value="' +
        kit.esc(pending.challenge) + '">' +
        '<label for="dev-proof">' + t.html('portalDevices.proof.jws') +
        '</label><textarea id="dev-proof" name="proof" rows="4"></textarea>' +
        '<p class="sub">' + t.html('portalDevices.proof.appAttestIntro') +
        '</p><label for="dev-aa-key">' +
        t.html('portalDevices.proof.aaKeyId') + '</label>' +
        '<input type="text" id="dev-aa-key" name="app_attest_key_id" ' +
        'maxlength="128"><label for="dev-aa-object">' +
        t.html('portalDevices.proof.aaObject') + '</label>' +
        '<textarea id="dev-aa-object" name="app_attest_object" rows="4">' +
        '</textarea><label for="dev-key-label">' +
        t.html('portalDevices.proof.keyName') + '</label>' +
        '<input type="text" id="dev-key-label" name="key_label" ' +
        'maxlength="128">' + DevicesPages.targetFields(view, t) +
        '<button type="submit">' + t.html('portalDevices.proof.register') +
        '</button>') +
      DevicesPages.form('cancel-proof', '<button class="secondary" ' +
        'type="submit">' + t.html('portalDevices.cancel') + '</button>');
  }

  // The person's keys that cannot be linked, each named with the reason —
  // or nothing when there are none. THE NAMES ARE MARKUP, so they sit
  // between two messages rather than in one as a parameter (#539).
  /**
   * The roaming keys passed over.
   *
   * @param roaming - their names
   * @param t - the translator
   * @returns the HTML
   */
  static passedOver(roaming: string[], t: Json): string {
    if (!roaming || !roaming.length) {
      return '';
    }
    return '<p class="note" id="devices-roaming">' +
      t.html('portalDevices.roaming.lead', { count: roaming.length }) + ' ' +
      roaming.map(function (name: string): string {
        return '<strong>' + kit.esc(name) + '</strong>';
      }).join(', ') + '. ' +
      t.html('portalDevices.roaming.why', { count: roaming.length }) + '</p>';
  }

  // THE WEBAUTHN LINK block, step one: which credential, and which device.
  /**
   * The link step.
   *
   * @param view - the page's view
   * @param t - the translator
   * @returns the HTML
   */
  static linkBlock(view: Json, t: Json): string {
    const link = view.link || { enrolled: 0, keys: [], roaming: [] };
    const roaming = DevicesPages.passedOver(link.roaming, t);
    if (!link.keys.length) {
      // The link is markup, so the sentence is three messages around it.
      return '<h2>' + t.html('portalDevices.link.heading') + '</h2>' +
        '<p class="note">' + (link.enrolled
          ? t.html('portalDevices.link.noneLinkable')
          : t.html('portalDevices.link.noPasskeys')) + '</p>' + roaming +
        '<p class="note">' + t.html('portalDevices.link.howBefore') +
        ' <a href="' + kit.BASE + '/keys">' +
        t.html('portalDevices.link.howLink') + '</a> ' +
        t.html('portalDevices.link.howAfter') + '</p>';
    }
    return '<h2>' + t.html('portalDevices.link.heading') + '</h2>' +
      roaming + '<p class="sub">' + t.html('portalDevices.link.intro') +
      '</p>' + DevicesPages.form('link-begin',
        '<label for="dev-cred">' + t.html('portalDevices.link.which') +
        '</label><select id="dev-cred" name="credential_id">' +
        link.keys.map(function (k: Json): string {
          return '<option value="' + kit.esc(k.credentialId) + '">' +
            kit.esc(k.name) + ' — ' + (k.trusted
              ? t.html('portalDevices.link.trusted')
              : t.html('portalDevices.link.notTrusted')) + '</option>';
        }).join('') + '</select>' + DevicesPages.targetFields(view, t) +
        '<button type="submit">' + t.html('portalDevices.link.button') +
        '</button>');
  }

  // THE WEBAUTHN LINK, step two: the armed ceremony.
  /**
   * The armed link ceremony.
   *
   * @param view - the page's view
   * @param t - the translator
   * @returns the HTML
   */
  static ceremonyBlock(view: Json, t: Json): string {
    const c = view.linking;
    const user = (view.me && view.me.user) || {};
    return '<h2>' + t.html('portalDevices.ceremony.heading') + '</h2>' +
      '<p class="note">' + t.html('portalDevices.ceremony.intro') + '</p>' +
      '<div id="wa-data" data-challenge="' + kit.esc(c.challenge) + '"' +
      ' data-rpid="' + kit.esc(c.rpId) + '"' +
      ' data-user="' + kit.esc(c.user || user.username || '') + '"' +
      ' data-allow="' + kit.esc(c.allow) + '"' +
      ' data-exclude=""' +
      ' data-options="' + kit.esc(JSON.stringify(c.options || {})) + '"' +
      ' data-mode="get"></div>' +
      '<button id="wa-go" type="button">' +
      t.html('portalDevices.ceremony.use') + '</button>' +
      DevicesPages.form('link-finish',
        '<input type="hidden" name="challenge" value="' +
        kit.esc(c.challenge) + '">' +
        '<input type="hidden" name="credential" id="wa-credential">' +
        '<button class="secondary" type="submit">' +
        t.html('portalDevices.ceremony.didNotAsk') + '</button>', 'wa-form') +
      DevicesPages.form('link-cancel', '<button class="secondary" ' +
        'type="submit">' + t.html('portalDevices.cancel') + '</button>');
  }

  /**
   * One device's keys.
   *
   * @param one - the device
   * @returns the HTML
   */
  static keysCell(one: Json): string {
    return (one.keys || []).length ? one.keys.map(function (k: Json) {
      return kit.esc(k.kind) + ' (' + kit.esc(k.level) + ')';
    }).join('<br>') : '—';
  }

  /**
   * The page's body.
   *
   * @param view - `GET /account-api/devices`' answer
   * @param ctx - the render context
   * @returns the HTML
   */
  static render(view: Json, ctx: Json): string {
    const t = ctx.t;
    const held: Json[] = view.devices || [];
    const rows = held.map(function (one: Json): string {
      return '<tr><td>' + kit.esc(one.label) + '</td><td>' +
        kit.esc((one.applications || []).join(', ') || '—') + '</td><td>' +
        (one.nativeSso ? (one.sessionLive
          ? t.html('portalDevices.devices.signedIn')
          : t.html('portalDevices.devices.signedOut')) : '—') + '</td><td>' +
        DevicesPages.keysCell(one) + '</td><td>' +
        kit.esc(one.attestation) + '</td><td>' + kit.esc(one.enrolment) +
        '</td><td>' + kit.esc(one.lastUsed ? t.date(one.lastUsed) : '') +
        '</td><td>' + DevicesPages.form('remove',
          '<input type="hidden" name="id" value="' + kit.esc(one.id) + '">' +
          '<button class="danger" type="submit">' +
          t.html('portalDevices.devices.remove') + '</button>') +
        '</td></tr>';
    });
    const remember = view.remember
      ? '<div class="card"><h2>' + t.html('portalDevices.remember.heading') +
        '</h2><p class="sub">' + t.html('portalDevices.remember.intro') +
        '</p>' + DevicesPages.form('remember-browser',
          '<button type="submit">' + t.html('portalDevices.remember.button') +
          '</button>') + '</div>'
      : '';
    return '<div class="card"><h2>' +
      t.html('portalDevices.devices.heading') + '</h2>' +
      '<p class="sub">' + t.html('portalDevices.devices.intro') + '</p>' +
      (held.length
        ? '<table><tr><th>' + t.html('portalDevices.devices.colDevice') +
          '</th><th>' + t.html('portalDevices.devices.colApplications') +
          '</th><th>' + t.html('portalDevices.devices.colShared') +
          '</th><th>' + t.html('portalDevices.devices.colKeys') +
          '</th><th>' + t.html('portalDevices.devices.colAttestation') +
          '</th><th>' + t.html('portalDevices.devices.colRegisteredBy') +
          '</th><th>' + t.html('portalDevices.devices.colLastUsed') +
          '</th><th></th></tr>' + rows.join('') + '</table>'
        : '<p id="devices-none">' + t.html('portalDevices.devices.none') +
          '</p>') + '</div>' +
      '<div class="card">' + (view.linking
        ? DevicesPages.ceremonyBlock(Object.assign({ me: ctx.me }, view), t)
        : DevicesPages.proofBlock(view, t) + DevicesPages.linkBlock(view, t)) +
      '</div>' + remember;
  }

  /**
   * The pages, for `web_portal_pages.ts`.
   */
  static readonly PAGES: PortalPage[] = [
    { path: PATH, operation: '/account-api/devices',
      render: DevicesPages.render }
  ];
}

export = DevicesPages;
