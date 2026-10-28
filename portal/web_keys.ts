// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_keys.ts
//
// ---------------------------------------------------------------------------
// `/portal/keys`, DRAWN IN THE BROWSER (#568), from `GET /account-api/keys`
// (`account_keys.ts`): the passkey page (#470) — one heading over every kind,
// the keys grouped *on your devices* and *on security keys*, each row a name,
// its provider, *Created* and *Last used*, Rename and Remove, and a *Details*
// fold with everything technical; two calls to action; and the ceremony
// while a registration is waiting.
//
// THE CEREMONY IS THE SAME MARKUP THE SERVER DREW — `#wa-data`, `#wa-form`
// with its hidden `#wa-credential` — and the runtime runs it
// (`web_portal_webauthn.ts`) AS SOON AS THE ARMED PAGE IS DRAWN (`#wa-data`
// carries `data-autostart`; rcbj, 2026-10-28: the call to action pressed is
// the request, and a second button asked it twice) and sends `#wa-form` to
// `/account-api`. The activation's key step and the device link still draw
// `#wa-go` and run on its click. A
// registration the guidance shows is reported through that finish without
// the form being submitted and without the answer being drawn (#961). The
// Signal API's `#wa-signal` likewise. RENAME is a `<details>` with a form in
// it, markup that needs nothing more.
//
// A `web_` MODULE: it requires other `web_` modules only and logs nothing.
// ---------------------------------------------------------------------------

import kit = require('./web_portal_kit');

type Json = any;
type PortalPage = import('../types/account-api').PortalPage;

const PATH = kit.BASE + '/keys';

/**
 * `/portal/keys`. A static utility class.
 */
class KeysPages {
  // WHAT THE ATTESTATION PROVED ABOUT ONE OF THE PERSON'S OWN KEYS (#105), in
  // their words: the model the FIDO metadata names where the statement
  // chained to an anchor, "verified" where it was checked and anchored
  // nowhere, and "claimed" where nothing was checked.
  /**
   * The attestation, as a sentence.
   *
   * @param att - the row's `attestation`
   * @param t - the translator
   * @returns the sentence, escaped
   */
  static attestationText(att: Json, t: Json): string {
    let text = t.text('portal.attest.claimed');
    if (att && att.verified && att.trusted) {
      text = att.model
        ? t.text('portal.attest.trustedModel', { model: att.model })
        : t.text('portal.attest.trusted');
    } else if (att && att.verified) {
      text = att.type === 'none' || att.type === 'self'
        ? t.text('portal.attest.noneSent', { type: att.type })
        : t.text('portal.attest.unanchored');
    }
    // #256: Google's Android attestation status list on an android-key key.
    if (att && (att.androidStatus === 'revoked' ||
                att.androidStatus === 'suspended')) {
      text += t.text('portal.attest.google',
                     { status: String(att.androidStatus).toUpperCase() });
    }
    return kit.esc(text);
  }

  // RENAME, as a fold with a form in it (#470). `open` draws it unfolded,
  // for the nickname prompt after an enrolment. An empty name puts the
  // default back (`credentials.renameKey()`).
  /**
   * The rename form.
   *
   * @param one - the key's row
   * @param open - whether it is drawn unfolded
   * @param t - the translator
   * @returns the HTML
   */
  static renameForm(one: Json, open: boolean, t: Json): string {
    const id = 'rn-' + String(one.credentialId).slice(0, 16)
      .replace(/[^A-Za-z0-9_-]/g, '');
    const form = '<form method="post" action="' + kit.BASE + '/rename-key">' +
      '<input type="hidden" name="credentialId" value="' +
      kit.esc(one.credentialId) + '"><label for="' + id + '">' +
      (open ? t.html('portal.keys.nickname') : t.html('portal.keys.newName')) +
      '</label><input type="text" id="' + id + '" name="label" ' +
      'maxlength="60" value="' + kit.esc(one.name) + '">' +
      '<button>' + t.html('portal.keys.save') + '</button></form>';
    return open ? form
                : '<details><summary>' + t.html('portal.keys.rename') +
                  '</summary>' + form + '</details>';
  }

  // ONE ROW OF THE PASSKEY LIST (#470). The dates stay ISO days: they are
  // what a person quotes, and the words around them are translated (#539).
  /**
   * One passkey.
   *
   * @param one - the key's row
   * @param t - the translator
   * @returns the HTML
   */
  static passkeyRow(one: Json, t: Json): string {
    const securityKey = one.group === 'security-key';
    const day = function (ms: Json): string {
      return new Date(Number(ms) || 0).toISOString().slice(0, 10);
    };
    const backup = one.backupEligible === true
      ? (one.backupState === true ? t.html('portal.keys.backedUp')
                                  : t.html('portal.keys.canBackUp'))
      : (one.backupEligible === false ? t.html('portal.keys.cannotBackUp')
                                      : t.html('portal.keys.notRecorded'));
    const transports = Array.isArray(one.transports) && one.transports.length
      ? kit.esc(one.transports.join(', '))
      : t.html('portal.keys.notReported');
    const algorithm = one.algorithm || {};
    const att = one.attestation || {};
    return '<li><span class="ico">' +
      (securityKey ? kit.ICONS.securityKey : kit.ICONS.devices) +
      '</span><div class="body"><div class="name">' + kit.esc(one.name) +
      '</div><div class="meta">' +
      (one.provider && one.provider !== one.name
        ? kit.esc(one.provider) + ' · ' : '') +
      t.html('portal.keys.created', { day: day(one.enrolledAt) }) + ' · ' +
      (one.lastUsedAt
        ? t.html('portal.keys.lastUsed', { day: day(one.lastUsedAt) })
        : t.html('portal.keys.notUsed')) +
      ' · ' + (one.role === 'primary' ? t.html('portal.keys.rolePrimary')
                                      : t.html('portal.keys.roleMfa')) +
      '</div>' +
      // A ROW A LATER REGISTRATION MAY HAVE REPLACED ON ITS AUTHENTICATOR
      // (#1101): the Remove button below is the way to clear it.
      (one.possiblyReplaced
        ? '<div class="meta passkey-possibly-replaced">' +
          t.html('portal.keys.possiblyReplaced',
                 { day: day(one.possiblyReplaced.at) }) + '</div>'
        : '') +
      // A SYNCED KEY THE REALM NO LONGER TAKES (#528).
      (one.syncedRefused
        ? '<div class="meta" id="passkey-synced-refused">' +
          t.html('portal.keys.syncedRefused') + '</div>'
        : '') +
      // ONE THE ATTESTATION RULES REFUSED AT SIGN-IN (#530).
      (one.attestationRefused
        ? '<div class="meta" id="passkey-attestation-refused">' +
          kit.esc(one.attestationRefused) + ' ' +
          t.html('portal.keys.removeAndRegister') + '</div>'
        : '') +
      // A CLASSICAL KEY WHERE A POST-QUANTUM ONE IS REQUIRED (#718).
      (one.postQuantumRefused
        ? '<div class="meta" id="passkey-post-quantum-refused">' +
          t.html('portal.keys.postQuantumRefused') + '</div>'
        : '') +
      // ONE WHOSE MINIMUM PIN THE REALM NO LONGER ACCEPTS (#529).
      (one.pinRefused
        ? '<div class="meta" id="passkey-pin-refused">' +
          kit.esc(one.pinRefused) + '</div>'
        : '') +
      KeysPages.renameForm(one, false, t) +
      '<details><summary>' + t.html('portal.keys.details') +
      '</summary><table>' +
      '<tr><th>' + t.html('portal.keys.used') + '</th><td>' +
      (one.role === 'primary' ? t.html('portal.keys.usedPrimary')
                              : t.html('portal.keys.usedMfa')) +
      '</td></tr>' +
      // The device serial an enterprise attestation named (#532).
      (att.deviceSerial
        ? '<tr><th>' + t.html('portal.keys.serial') + '</th><td>' +
          kit.esc(att.deviceSerial) + '</td></tr>'
        : '') +
      '<tr><th>' + t.html('portal.keys.kind') + '</th><td>' +
      kit.esc(one.kind) + '</td></tr>' +
      '<tr><th>' + t.html('portal.keys.backup') + '</th><td>' + backup +
      '</td></tr>' +
      '<tr><th>' + t.html('portal.keys.transports') + '</th><td>' +
      transports + '</td></tr>' +
      // WHETHER IT SIGNS IN WITH NO USERNAME (#474).
      '<tr><th>' + t.html('portal.keys.withoutUsername') + '</th><td>' +
      kit.esc(one.withoutUsername) + '</td></tr>' +
      '<tr><th>' + t.html('portal.keys.algorithm') + '</th><td><code>' +
      kit.esc(algorithm.text) + '</code>' +
      (algorithm.postQuantum ? ' ' + t.html('portal.keys.postQuantum') : '') +
      (algorithm.insecure
        ? ' <strong>' + t.html('portal.keys.insecure') + '</strong>' : '') +
      '</td></tr>' +
      // CLASSICAL OR POST-QUANTUM, FROM THE KEY'S ALGORITHM (#1076). It was
      // drawn from the LANE (#643) alone, which is `pqc` only in a realm
      // running `webauthn.pqcAlongsideClassical` — off by default — so an
      // ML-DSA passkey said "classical" here beside an Algorithm row saying
      // post-quantum. A key in the post-quantum lane still says that it is
      // listed as a second account.
      '<tr><th>' + t.html('portal.keys.lane') + '</th><td>' +
      (!algorithm.postQuantum ? t.html('portal.keys.laneClassical')
        : (one.lane === 'pqc' ? t.html('portal.keys.lanePqc')
                              : t.html('portal.keys.cryptoPostQuantum'))) +
      '</td></tr>' +
      '<tr><th>' + t.html('portal.keys.authenticator') + '</th><td>' +
      KeysPages.attestationText(one.attestation, t) + '</td></tr>' +
      '<tr><th>AAGUID</th><td><code>' + kit.esc(one.aaguid || 'none') +
      '</code></td></tr>' +
      (one.upgrade && one.upgrade.upgradedAt
        ? '<tr><th>Post-quantum upgrade</th><td>Upgraded ' +
          kit.esc(new Date(Number(one.upgrade.upgradedAt)).toISOString()
            .slice(0, 10)) + ' from <code>' +
          kit.esc(one.upgrade.previousAlgorithm || '') + '</code> (' +
          kit.esc(one.upgrade.mode || '') + ')</td></tr>' : '') +
      '</table></details></div><div class="acts">' +
      '<form method="post" action="' + kit.BASE + '/remove-key">' +
      '<input type="hidden" name="credentialId" value="' +
      kit.esc(one.credentialId) + '"><button class="danger" aria-label="' +
      kit.esc(t.text('portal.keys.removeLabel', { name: one.name })) + '">' +
      t.html('portal.keys.remove') + '</button></form></div></li>';
  }

  // *LEARN MORE* (#470): the benefit first, then a fold for this service's
  // own two roles and the backup rule.
  /**
   * The *Learn more* fold.
   *
   * @param view - the page's view
   * @param t - the translator
   * @returns the HTML
   */
  static learnMore(view: Json, t: Json): string {
    const held = (view.keys || []).length;
    return '<details><summary>' + t.html('portal.keys.learnMore') +
      '</summary>' +
      '<p class="note">' + t.html('portal.keys.learnRoles') + '</p>' +
      '<p class="note">' + t.html('portal.keys.learnWhere') + '</p>' +
      // The link to Devices is markup, so the sentence is two messages
      // around it (#539).
      '<p class="note">' + t.html('portal.keys.learnDevicesBefore') +
      ' <a href="' + kit.BASE + '/devices">' +
      t.html('portal.nav.devices.label') + '</a>' +
      t.html('portal.keys.learnDevicesAfter') + '</p>' +
      (held > 1
        ? '<p class="note">' + t.html('portal.keys.learnMany', { n: held }) +
          '</p>'
        : (held === 1
            ? '<p class="note">' + t.html('portal.keys.learnOne') + '</p>'
            : '')) +
      (view.password ? '' : '<p class="note">' +
        t.html('portal.keys.learnNoPassword') + '</p>') + '</details>';
  }

  // WHERE THE PASSKEY LIVES, as radios (#470): `/portal/activate` asks with
  // these, because its one form carries a password and a role as well; the
  // passkey page asks with two buttons. Nothing to choose with one kind.
  /**
   * The kind, as radios.
   *
   * @param kinds - the kinds the realm allows
   * @param t - the translator
   * @returns the HTML, or ''
   */
  static kindChoice(kinds: Json[], t: Json): string {
    if (!kinds || kinds.length < 2) {
      return '';
    }
    const rows: Json = {
      'passkey': [t.html('portal.kind.passkey'),
                  t.html('portal.kind.passkeyWhat')],
      'security-key': [t.html('portal.kind.securityKey'),
                       t.html('portal.kind.securityKeyWhat')]
    };
    return '<p class="sub"><strong>' + t.html('portal.kind.which') +
      '</strong></p>' + kinds.map(function (kind: string, i: number): string {
        return '<label class="chk"><input type="radio" name="kind" ' +
          'value="' + kit.esc(kind) + '"' + (i === 0 ? ' checked' : '') +
          '> ' + rows[kind][0] + ' <span class="sub">' + rows[kind][1] +
          '</span></label>';
      }).join('');
  }

  // WHICH LANE (#643): a classical passkey or a post-quantum one, asked only
  // where the realm offers both, as radios in the form whose buttons begin
  // the enrolment — so the call to action pressed sends the choice. Shared
  // with the activation's setup form.
  /**
   * The lane, as radios, or '' with one lane.
   *
   * @param lanes - the lanes the realm offers
   * @param t - the translator
   * @returns the HTML
   */
  static laneChoice(lanes: Json, t: Json): string {
    if (!Array.isArray(lanes) || lanes.length < 2) {
      return '';
    }
    const rows: Json = {
      classical: [t.html('portal.lane.classical'),
                  t.html('portal.lane.classicalWhat')],
      pqc: [t.html('portal.lane.pqc'), t.html('portal.lane.pqcWhat')]
    };
    return '<p class="sub"><strong>' + t.html('portal.lane.which') +
      '</strong></p>' + lanes.map(function (lane: string, i: number): string {
        return '<label class="chk"><input type="radio" name="lane" ' +
          'value="' + kit.esc(lane) + '"' + (i === 0 ? ' checked' : '') +
          '> ' + rows[lane][0] + ' <span class="sub">' + rows[lane][1] +
          '</span></label>';
      }).join('');
  }

  // THE CEREMONY'S MARKUP, the server-rendered portal's own: `#wa-data` read
  // by the runtime, `#wa-go`, and `#wa-form` whose hidden `#wa-credential` the
  // ceremony fills before the runtime sends it. Shared with the activation's
  // key step, which differs only in the form's fields.
  /**
   * The `#wa-data` element for a registration.
   *
   * @param pending - `{ challenge, rpId, user, userHandle, display, exclude,
   *   options }`
   * @param autostart - true where the runtime is to run the ceremony as
   *   soon as the page is drawn, with no button (the Passkeys page)
   * @returns the HTML
   */
  static ceremonyData(pending: Json, autostart?: boolean): string {
    return '<div id="wa-data"' +
      (autostart ? ' data-autostart="1"' : '') +
      ' data-challenge="' + kit.esc(pending.challenge) + '"' +
      ' data-rpid="' + kit.esc(pending.rpId) + '"' +
      ' data-user="' + kit.esc(pending.user) + '"' +
      ' data-userid="' + kit.esc(pending.userHandle || '') + '"' +
      ' data-display="' + kit.esc(pending.display) + '"' +
      ' data-allow=""' +
      ' data-exclude="' + kit.esc((pending.exclude || []).join(',')) + '"' +
      ' data-options="' + kit.esc(JSON.stringify(pending.options || {})) +
      // The fallback's facts (#944), for the failure's report.
      '" data-fallback="' + kit.esc(JSON.stringify(pending.fallback || {})) +
      '" data-mode="create"></div>';
  }

  // WHEN THE DEVICE CANNOT MAKE THE POST-QUANTUM PASSKEY ASKED FOR (#944):
  // the guidance, drawn HIDDEN beside the ceremony and shown by
  // `web_portal_webauthn.ts` (through `common/web_webauthn.ts`'s
  // `offerFallback()`) only after the registration fails with an error it
  // is for. Where the account API says the realm allows the classical
  // retry, a form that begins the enrolment again — the same role, kind
  // and lane, `algorithms` `classical`, which the API refuses again where
  // the realm forbids it; where it does not, the sentence that this device
  // cannot make the passkey this service requires. Nothing for a ceremony
  // that asks for no ML-DSA, or that is the retry already.
  /**
   * The hidden guidance of a registration that may fail on ML-DSA, or ''.
   *
   * @param pending - the waiting registration, with its `fallback`
   * @param t - the translator
   * @returns the HTML
   */
  static fallback(pending: Json, t: Json): string {
    const f = (pending && pending.fallback) || null;
    if (!f || f.asksPostQuantum !== true || f.retrying === true) {
      return '';
    }
    const allowed = f.classical === true;
    return '<div class="warn" id="wa-fallback" hidden>' +
      '<p id="wa-fallback-unsupported" hidden>' +
      (allowed ? t.html('portal.key.unsupported')
               : t.html('portal.key.cannotMake')) + '</p>' +
      '<p id="wa-fallback-uncertain" hidden>' +
      (allowed ? t.html('portal.key.maybeUnsupported')
               : t.html('portal.key.maybeCannotMake')) + '</p>' +
      '<p id="wa-fallback-hybrid" hidden>' + t.html('portal.key.hybrid') +
      '</p>' +
      (allowed
        ? '<form method="post" action="' + PATH + '" ' +
          'id="wa-retry-classical-form">' +
          '<input type="hidden" name="action" value="begin">' +
          '<input type="hidden" name="role" value="' +
          kit.esc(pending.role || 'mfa') + '">' +
          (pending.kind
            ? '<input type="hidden" name="kind" value="' +
              kit.esc(pending.kind) + '">' : '') +
          '<input type="hidden" name="lane" value="' +
          kit.esc(pending.lane || 'classical') + '">' +
          '<input type="hidden" name="algorithms" value="classical">' +
          '<button class="secondary" id="wa-retry-classical">' +
          t.html('portal.key.retryClassical') + '</button></form>' +
          '<p class="sub">' + t.html('portal.key.retryClassicalWhat') +
          '</p>'
        : '') + '</div>';
  }

  // ADDING A KEY: the ceremony while one is waiting, else the form with the
  // role and the two calls to action — two submit buttons of one form, so
  // the button pressed is the kind.
  /**
   * The enrolment block.
   *
   * @param view - the page's view
   * @param t - the translator
   * @returns the HTML
   */
  static enrolBlock(view: Json, t: Json): string {
    const enrol = view.enrol || {};
    if (!enrol.enabled) {
      return '<h2>' + t.html('portal.enrol.heading') + '</h2>' +
        '<p class="note">' + t.html('portal.enrol.off') + '</p>';
    }
    if (enrol.atCap) {
      return '<h2>' + t.html('portal.enrol.heading') + '</h2>' +
        '<p class="note">' + t.html('portal.enrol.atCap',
          { n: enrol.count }) + '</p>';
    }
    const pending = enrol.pending;
    if (pending) {
      const securityKey = pending.kind === 'security-key';
      return '<h2>' + (securityKey ? t.html('portal.key.useHeading')
                                   : t.html('portal.key.createHeading')) +
        '</h2><p class="note">' + (securityKey
          ? t.html('portal.key.promptSecurityKey')
          : t.html('portal.key.promptPasskey')) + ' ' +
        t.html('portal.enrol.different') + '</p>' +
        // THE CEREMONY STARTS ON ITS OWN (rcbj, 2026-10-28): the call to
        // action a person pressed IS the request, so the armed page carries
        // `data-autostart` and the runtime runs the browser's prompt as
        // soon as it is drawn, with no second button to press and no "my
        // browser did not ask" button beside it. A prompt the browser
        // refuses or the person dismisses is posted as the finish's error,
        // which abandons the enrolment and draws the two calls to action
        // again with the browser's own words, as a refused ceremony always
        // did. The activation's key step and the device link keep their
        // button (`#wa-go`), because each is one step of a longer form.
        KeysPages.ceremonyData(pending, true) +
        '<form method="post" action="' + PATH + '" id="wa-form">' +
        '<input type="hidden" name="action" value="finish">' +
        '<input type="hidden" name="enrolment_id" value="' +
        kit.esc(pending.id) + '">' +
        '<input type="hidden" name="credential" id="wa-credential">' +
        '</form><form method="post" action="' + PATH + '">' +
        '<input type="hidden" name="action" value="cancel">' +
        '<button class="secondary">' + t.html('portal.enrol.cancel') +
        '</button></form>' + KeysPages.fallback(pending, t) +
        '<p class="sub">' +
        (securityKey
          ? (pending.role === 'primary'
              ? t.html('portal.enrol.creatingKeyPrimary')
              : t.html('portal.enrol.creatingKeyMfa'))
          : (pending.role === 'primary'
              ? t.html('portal.enrol.creatingDevicePrimary')
              : t.html('portal.enrol.creatingDeviceMfa'))) + '</p>';
    }
    const roles: string[][] = (enrol.roles || []).map(function (role: string) {
      return role === 'mfa'
        ? ['mfa', t.html('portal.enrol.asSecond'),
           view.password ? t.html('portal.enrol.asSecondWhat')
                         : t.html('portal.enrol.asSecondNoPassword')]
        : ['primary', t.html('portal.enrol.instead'),
           t.html('portal.enrol.insteadWhat')];
    });
    if (!roles.length) {
      return '<h2>' + t.html('portal.enrol.heading') + '</h2>' +
        '<p class="note">' + t.html('portal.enrol.noRole') + '</p>';
    }
    const labels: Json = { 'passkey': t.html('portal.enrol.createPasskey'),
                           'security-key':
                             t.html('portal.enrol.useSecurityKey') };
    return '<h2>' + t.html('portal.enrol.heading') + '</h2>' +
      (enrol.count
        ? '<p class="note">' + t.html('portal.enrol.addsNew') + '</p>' : '') +
      '<form method="post" action="' + PATH + '">' +
      '<input type="hidden" name="action" value="begin">' +
      (roles.length > 1
        ? '<p class="sub"><strong>' + t.html('portal.enrol.howUse') +
          '</strong></p>' + roles.map(function (row: string[]): string {
            return '<label class="chk"><input type="radio" name="role" ' +
              'value="' + kit.esc(row[0]) + '"' +
              (row[0] === roles[0][0] ? ' checked' : '') + '> ' + row[1] +
              ' <span class="sub">' + row[2] + '</span></label>';
          }).join('')
        : '<input type="hidden" name="role" value="' + kit.esc(roles[0][0]) +
          '"><p class="note">' + roles[0][1] + '. ' + roles[0][2] + '</p>') +
      KeysPages.laneChoice(enrol.lanes, t) +
      '<div class="ctas">' + (enrol.kinds || []).map(function (kind: string,
                                                               i: number) {
        return '<button name="kind" value="' + kit.esc(kind) + '"' +
          (i > 0 ? ' class="secondary"' : '') + '>' +
          (kind === 'passkey' ? kit.ICONS.passkey : kit.ICONS.securityKey) +
          labels[kind] + '</button>';
      }).join('') + '</div></form>';
  }

  // THE SIGNAL API'S DATA (#470), read by the runtime: never while a
  // ceremony is armed, and only under a user handle this service minted.
  // ONE ELEMENT PER LANE (#643): `#wa-signal` for the classical lane and
  // `#wa-signal-pqc` for the post-quantum one, each with its own handle,
  // name and credential ids.
  /**
   * The `#wa-signal` elements, one per lane, or ''.
   *
   * @param signals - the view's `signals`
   * @returns the HTML
   */
  static signalBlock(signals: Json): string {
    return (Array.isArray(signals) ? signals : []).map(function (
      signal: Json): string {
      return '<div id="' + (signal.lane === 'pqc' ? 'wa-signal-pqc'
                                                  : 'wa-signal') + '" hidden' +
        ' data-rpid="' + kit.esc(signal.rpId) + '"' +
        ' data-userid="' + kit.esc(signal.userId) + '"' +
        ' data-accepted="' + kit.esc((signal.accepted || []).join(',')) +
        '"' +
        ' data-name="' + kit.esc(signal.name) + '"' +
        ' data-display="' + kit.esc(signal.display) + '"></div>';
    }).join('');
  }

  /**
   * The page's body.
   *
   * @param view - `GET /account-api/keys`' answer
   * @param ctx - the render context
   * @returns the HTML
   */
  static render(view: Json, ctx: Json): string {
    const t = ctx.t;
    const keys: Json[] = view.keys || [];
    const devices = keys.filter(function (one: Json): boolean {
      return one.group === 'device';
    });
    const securityKeys = keys.filter(function (one: Json): boolean {
      return one.group === 'security-key';
    });
    // THE NICKNAME, ASKED FOR AFTER THE CEREMONY (#470): the answer to a
    // registration names the key, and its rename form is drawn open at the
    // top of the page with the default name in it.
    const fresh = view.named ? keys.filter(function (one: Json): boolean {
      return one.credentialId === view.named;
    })[0] : null;
    const nickname = fresh
      ? '<div class="ok">' + (fresh.group === 'security-key'
          ? t.html('portal.keys.nicknameSecurityKey')
          : t.html('portal.keys.nicknamePasskey')) +
        KeysPages.renameForm(fresh, true, t) + '</div>'
      : '';
    const group = function (title: string, icon: string, list: Json[]) {
      return list.length
        ? '<h2 class="pkgroup">' + icon + kit.esc(title) + '</h2>' +
          '<ul class="pk">' + list.map(function (one: Json): string {
            return KeysPages.passkeyRow(one, t);
          }).join('') + '</ul>'
        : '';
    };
    return '<div class="card">' + nickname +
      '<p class="sub">' + kit.ICONS.passkey + t.html('portal.keys.intro') +
      '</p>' + KeysPages.learnMore(view, t) +
      (keys.length
        ? group(t.text('portal.keys.onDevices'), kit.ICONS.devices,
                devices) +
          group(t.text('portal.keys.onSecurityKeys'), kit.ICONS.securityKey,
                securityKeys) +
          '<p class="note">' + (view.mfaRequired
            ? t.html('portal.keys.someSecond')
            : t.html('portal.keys.noneSecond')) + ' ' +
          t.html('portal.keys.lastWayIn') + '</p>'
        : '<p class="note">' + t.html('portal.keys.noneYet') + '</p>') +
      KeysPages.enrolBlock(view, t) + KeysPages.signalBlock(view.signals) +
      '</div>';
  }

  /**
   * The pages, for `web_portal_pages.ts`.
   */
  static readonly PAGES: PortalPage[] = [
    { path: PATH, operation: '/account-api/keys', render: KeysPages.render }
  ];
}

export = KeysPages;
