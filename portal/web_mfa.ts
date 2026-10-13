// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_mfa.ts
//
// ---------------------------------------------------------------------------
// `/portal/mfa`, DRAWN IN THE BROWSER (#568), from `GET /account-api/mfa`
// (`account_mfa.ts`): the authenticator app — set up, being set up, or
// offered — the emailed second factor (#64), the recovery codes, and what
// all of it is. The cards are `Portal.mfaPage()`'s, moved.
//
// THE RECOVERY CODES CARD HAS FOUR STATES AND STATE 3 IS THE ONE TO GET
// RIGHT (2026-09-11): a set generated and shown, NOT YET STORED. Somebody who
// writes the codes down, closes the tab and never presses the button is
// holding strings that work nowhere — so the confirm step is the only thing
// the card holds at that moment, the codes are labelled as not-yet-active,
// and the Cancel beside it says what it throws away. The set arrives in
// `view.fresh`, only in the answer that generated it.
//
// THE COPY BUTTON (#224) is drawn hidden; the runtime reveals it and writes
// the box's text to the clipboard (`/portal/copy.js` until #568). Where it
// cannot, the box one code per line is the mechanism: a selection copies it
// as drawn.
//
// A `web_` MODULE: it requires other `web_` modules only and logs nothing.
// ---------------------------------------------------------------------------

import kit = require('./web_portal_kit');

type Json = any;
type PortalPage = import('../types/account-api').PortalPage;

const PATH = kit.BASE + '/mfa';

/**
 * `/portal/mfa`. A static utility class.
 */
class MfaPages {
  /**
   * A POST form to this page with an action and its fields.
   *
   * @param action - the action
   * @param inner - the rest of the form
   * @param cls - the form's class, or ''
   * @returns the form's HTML
   */
  static form(action: string, inner: string, cls?: string): string {
    return '<form method="post" action="' + PATH + '"' +
      (cls ? ' class="' + cls + '"' : '') + '>' +
      '<input type="hidden" name="action" value="' + action + '">' + inner +
      '</form>';
  }

  /**
   * An instant as a date, `YYYY-MM-DD`.
   *
   * @param ms - milliseconds since the epoch
   * @returns the date
   */
  static day(ms: Json): string {
    return new Date(Number(ms) || 0).toISOString().slice(0, 10);
  }

  /**
   * The authenticator app's status card.
   *
   * @param view - the page's view
   * @param t - the translator
   * @returns the card's HTML
   */
  static enrolledCard(view: Json, t: Json): string {
    const totp = view.totp || {};
    const detail = totp.detail;
    const doors = view.doors || {};
    return '<div class="card"><h2>' + t.html('portal.mfa.status') + '</h2>' +
      '<p class="sub">' +
      (totp.enrolled
        ? (totp.usable ? t.html('portal.mfa.setUp')
                       : t.html('portal.mfa.unreadable'))
        : t.html('portal.mfa.none')) + '</p>' +
      // THE PASSWORD-ONLY DOORS (#101): where a second factor cannot be asked
      // for, their own password is refused, and this says where to get what
      // those clients take instead.
      (doors.applies && (doors.refused || []).length
        ? '<p class="note">' + t.html('portal.mfa.doors',
            { doors: doors.refused.join(', ') }) + ' <a href="' + kit.BASE +
          '/app-passwords">' + t.html('portal.mfa.makeAppPassword') + '</a>' +
          t.html('portal.mfa.makeAppPasswordAfter') + '</p>'
        : '') +
      (totp.enrolled && detail
        ? '<table class="grid"><tr><th>' + t.html('portal.mfa.setUpOn') +
          '</th><td>' + kit.esc(MfaPages.day(detail.enrolledAt)) +
          '</td></tr><tr><th>' + t.html('portal.mfa.lastUsed') + '</th><td>' +
          (detail.lastUsedAt
            ? kit.esc(new Date(detail.lastUsedAt).toISOString()
                .slice(0, 19) + 'Z')
            : t.html('portal.mfa.never')) + '</td></tr><tr><th>' +
          t.html('portal.totp.algorithm') + '</th><td>' +
          t.html('portal.totp.algorithmValue', {
            alg: 'HMAC-' + String(detail.algorithm || 'SHA1')
              .replace(/^SHA/, 'SHA-'),
            digits: String(detail.digits || 6),
            period: String(detail.period || 30) }) + '</td></tr></table>' +
          MfaPages.form('remove', '<button class="danger">' +
                        t.html('portal.mfa.remove') + '</button>') +
          '<p class="note">' + t.html('portal.mfa.removeNote') + '</p>'
        : '') + '</div>';
  }

  /**
   * The enrolment in progress: the QR code, the secret by hand, and the code
   * that proves it.
   *
   * @param view - the page's view
   * @param t - the translator
   * @returns the card's HTML, or '' when nothing is being set up
   */
  static setupCard(view: Json, t: Json): string {
    const setup = view.setup;
    if (!setup) {
      return '';
    }
    // THE IMAGE, drawn on the server. `alt` says what it is rather than
    // repeating the secret: a screen reader announcing a shared secret
    // character by character in an open-plan office is not an improvement.
    return '<div class="card"><h2>' + t.html('portal.totp.scanHeading') +
      '</h2><p class="sub">' + t.html('portal.mfa.notSavedYet') + '</p>' +
      (setup.qr
        ? '<p><img src="' + kit.esc(setup.qr) + '" width="240" ' +
          'height="240" alt="' + kit.esc(t.text('portal.totp.qrAlt')) +
          '"></p>'
        : '') +
      '<h3>' + t.html('portal.totp.typeIt') + '</h3><p class="note">' +
      t.html('portal.mfa.byHand') + '</p><table class="grid"><tr><th>' +
      t.html('portal.totp.secret') + '</th><td><code>' +
      kit.esc(setup.grouped) + '</code></td></tr><tr><th>' +
      t.html('portal.totp.account') + '</th><td><code>' +
      kit.esc(view.username) + '</code></td></tr><tr><th>' +
      t.html('portal.totp.issuer') + '</th><td>' + kit.esc(setup.issuer) +
      '</td></tr><tr><th>' + t.html('portal.mfa.type') + '</th><td>' +
      t.html('portal.mfa.timeBased') + '</td></tr><tr><th>' +
      t.html('portal.totp.algorithm') + '</th><td>' +
      kit.esc('HMAC-' + String(setup.algorithm).replace(/^SHA/, 'SHA-')) +
      '</td></tr><tr><th>' + t.html('portal.mfa.digits') + '</th><td>' +
      kit.esc(String(setup.digits)) + '</td></tr><tr><th>' +
      t.html('portal.mfa.period') + '</th><td>' +
      t.html('portal.mfa.seconds', { n: setup.period }) +
      '</td></tr></table><h3>' + t.html('portal.mfa.prove') + '</h3>' +
      MfaPages.form('confirm', '<label for="code">' +
        t.html('portal.totp.codeLabel', { digits: String(setup.digits) }) +
        '</label><input type="text" id="code" name="code" ' +
        'autocomplete="one-time-code" inputmode="numeric" maxlength="' +
        kit.esc(String(setup.digits)) + '" placeholder="' +
        '0'.repeat(Number(setup.digits) || 6) + '"><button type="submit">' +
        t.html('portal.mfa.finish') + '</button>') +
      '<p class="note">' + t.html('portal.mfa.spent') + '</p></div>';
  }

  /**
   * The card that starts (or replaces) an authenticator app.
   *
   * @param view - the page's view
   * @param t - the translator
   * @returns the card's HTML
   */
  static startCard(view: Json, t: Json): string {
    const totp = view.totp || {};
    if (!totp.offered) {
      return '<div class="card"><h2>' + t.html('portal.mfa.notAvailable') +
        '</h2><p class="sub">' + t.html('portal.mfa.turnedOff') +
        '</p></div>';
    }
    return '<div class="card"><h2>' +
      (totp.enrolled ? t.html('portal.mfa.replaceHeading')
                     : t.html('portal.mfa.setOneUp')) + '</h2>' +
      '<p class="sub">' + t.html('portal.mfa.anyApp') + '</p>' +
      (totp.enrolled ? '<p class="note">' + t.html('portal.mfa.replaces') +
                       '</p>' : '') +
      MfaPages.form('start', '<button' +
        (totp.enrolled ? ' class="secondary"' : '') + '>' +
        (view.setup ? t.html('portal.mfa.startAgain')
          : (totp.enrolled ? t.html('portal.mfa.replaceMine')
                           : t.html('portal.mfa.setUpApp'))) +
        '</button>') + '</div>';
  }

  // THE EMAILED SECOND FACTOR (#64): drawn in every realm that offers it,
  // with the reason it cannot be turned on where it cannot — the realm's
  // policy, mail, or an unverified address — DISABLED rather than left out,
  // so a person reading it learns what is missing.
  /**
   * The emailed second factor's card.
   *
   * @param view - the page's view
   * @param t - the translator
   * @returns the card's HTML, or '' when it is not offered
   */
  static emailFactorCard(view: Json, t: Json): string {
    const status = view.emailFactor;
    if (!status) {
      return '';
    }
    const allowed = status.allowed || {};
    const offered = status.offered || {};
    const blocked = !offered.code && !offered.link
      ? t.html('portal.emailFactor.noMail')
      : (!status.verified ? t.html('portal.emailFactor.unverified') : '');
    const option = function (kind: string, label: string): string {
      const off = !allowed[kind] || !offered[kind] || !!blocked;
      return MfaPages.form('email-factor-on',
        '<input type="hidden" name="kind" value="' + kind + '">' +
        '<button id="email-factor-' + kind + '"' +
        (status.optedIn === kind ? ' class="secondary"' : '') +
        (off || status.optedIn === kind ? ' disabled' : '') + '>' + label +
        '</button>', 'inline') + ' ';
    };
    let said = t.html('portal.emailFactor.off');
    if (status.optedIn && status.usable) {
      said = status.kind === 'code'
        ? t.html('portal.emailFactor.onCode', { address: status.masked })
        : t.html('portal.emailFactor.onLink', { address: status.masked });
    } else if (status.optedIn) {
      said = status.optedIn === 'code'
        ? t.html('portal.emailFactor.unusedCode', { why: status.why })
        : t.html('portal.emailFactor.unusedLink', { why: status.why });
    }
    return '<div class="card" id="email-factor"><h2>' +
      t.html('portal.emailFactor.heading') + '</h2><p class="sub">' + said +
      '</p>' + (blocked ? '<p class="note">' + blocked + '</p>' : '') +
      (allowed.code ? option('code', t.html('portal.emailFactor.code')) : '') +
      (allowed.link ? option('link', t.html('portal.emailFactor.link')) : '') +
      (status.optedIn
        ? MfaPages.form('email-factor-off', '<button class="danger" ' +
            'id="email-factor-off">' + t.html('portal.emailFactor.turnOff') +
            '</button>', 'inline')
        : '') +
      '<p class="note">' + t.html('portal.emailFactor.weakest') +
      '</p></div>';
  }

  /**
   * The recovery codes card, in its four states (see the header).
   *
   * @param view - the page's view
   * @param t - the translator
   * @returns the card's HTML
   */
  static codesCard(view: Json, t: Json): string {
    const live = view.codes || {};
    const fresh = view.fresh;
    // STATE 3: a set generated and shown, nothing stored.
    if (fresh && (fresh.codes || []).length) {
      const handle = '<input type="hidden" name="handle" value="' +
        kit.esc(fresh.handle || '') + '">';
      return '<div class="card"><h2>' + t.html('portal.codes.saveHeading') +
        '</h2><p class="sub"><strong>' + t.html('portal.codes.notSavedYet') +
        '</strong></p><ul class="codes">' +
        fresh.codes.map(function (code: string): string {
          return '<li><code>' + kit.esc(code) + '</code></li>';
        }).join('') + '</ul>' +
        // #224: the same codes ONE PER LINE, which a selection copies as
        // drawn, and the Copy button the runtime reveals.
        '<p><label for="recovery-codes-text">' +
        t.html('portal.codes.plainText') + '</label><br><textarea ' +
        'id="recovery-codes-text" readonly rows="' + fresh.codes.length +
        '" cols="28">' + fresh.codes.map(function (code: string): string {
          return kit.esc(code);
        }).join('\n') + '</textarea><br><button type="button" ' +
        'class="copybtn secondary" hidden ' +
        'data-copy-from="recovery-codes-text">' +
        t.html('portal.codes.copyAll') + '</button></p>' +
        '<p class="note">' + t.html('portal.codes.onlyTime') + '</p>' +
        '<p class="note">' + t.html('portal.codes.eachOnce') + '</p>' +
        (fresh.replacing ? '<p class="note">' +
          t.html('portal.codes.confirmReplaces') + '</p>' : '') +
        MfaPages.form('confirm-codes', handle + '<button>' +
                      t.html('portal.codes.saved') + '</button>') +
        MfaPages.form('discard-codes', handle + '<button class="secondary">' +
                      t.html('portal.codes.throwAway') + '</button>') +
        '<p class="note">' + t.html('portal.codes.closeWithout') +
        '</p></div>';
    }
    // STATES 1, 2 AND 4.
    const generateForm = MfaPages.form('generate-codes', '<button' +
      (live.present ? ' class="secondary"' : '') + '>' +
      (live.present ? t.html('portal.codes.generateNew')
                    : t.html('portal.codes.generateMine')) + '</button>');
    let body: string;
    if (!live.present) {
      body = '<p class="sub">' +
        (live.advised ? t.html('portal.codes.advised')
                      : t.html('portal.codes.noneGenerated')) + '</p>' +
        (live.advised ? '<p class="note">' +
          t.html('portal.codes.willNotCreate') + '</p>' : '') +
        (live.enabled ? generateForm : '') +
        '<p class="note">' + t.html('portal.codes.howMany',
          { count: live.count, length: live.length }) + '</p>';
    } else if (!live.usable) {
      // The reason is the store's own and stays English (#539).
      body = '<p class="sub">' + t.html('portal.codes.unreadable',
          { why: live.why || 'the stored set is unusable' }) + '</p>' +
        '<p class="note">' + t.html('portal.codes.unreadableFix') + '</p>' +
        (live.enabled ? generateForm : '');
    } else {
      body = '<p class="sub">' + t.html('portal.codes.unusedOf',
          { remaining: live.remaining, total: live.total }) + '</p>' +
        '<table class="grid"><tr><th>' + t.html('portal.codes.savedOn') +
        '</th><td>' + (live.generatedAt
          ? kit.esc(MfaPages.day(live.generatedAt))
          : t.html('portal.codes.notRecorded')) + '</td></tr><tr><th>' +
        t.html('portal.codes.unused') + '</th><td>' +
        t.html('portal.codes.countOf',
          { remaining: live.remaining, total: live.total }) +
        '</td></tr><tr><th>' + t.html('portal.mfa.lastUsed') + '</th><td>' +
        (live.lastUsedAt
          ? kit.esc(new Date(live.lastUsedAt).toISOString().slice(0, 19) +
                    'Z')
          : t.html('portal.mfa.never')) + '</td></tr><tr><th>' +
        t.html('portal.codes.stored') + '</th><td>' +
        t.html('portal.codes.storedHow') + '</td></tr></table>' +
        // THE REPLACE CONTROL, WITH WHAT IT COSTS SAID BEFORE IT IS PRESSED:
        // there is no way to see a set already held, so pressing it destroys
        // the one that was lost.
        '<p class="note">' + t.html('portal.codes.noWayToSee') + '</p>' +
        (live.enabled ? generateForm : '') +
        (live.remaining === 0
          ? '<p class="note">' + t.html('portal.codes.allUsed') + '</p>'
          : (live.remaining <= 3
            ? '<p class="note">' + t.html('portal.codes.nearlyOut',
                { remaining: live.remaining, total: live.total }) + '</p>'
            : ''));
    }
    return '<div class="card' + (live.advised && !live.present ? ' warn' : '') +
      '"><h2>' + t.html('portal.codes.heading') + '</h2>' + body +
      (!live.enabled ? '<p class="note">' + t.html('portal.codes.turnedOff') +
                       '</p>' : '') + '</div>';
  }

  /**
   * What an authenticator app is, and what it is not.
   *
   * @param view - the page's view
   * @param t - the translator
   * @returns the card's HTML
   */
  static aboutCard(view: Json, t: Json): string {
    const totp = view.totp || {};
    return '<div class="card"><h2>' + t.html('portal.mfa.whatThisIs') +
      '</h2><p class="note">' + t.html('portal.mfa.about',
        { digits: String(totp.digits), period: String(totp.period) }) +
      '</p><p class="note">' + t.html('portal.mfa.aboutSecond') +
      '</p><p class="note">' +
      // Per mode (#543 round 2): "any password is accepted" is development's.
      t.html(view.verifiesCredentials ? 'portal.mfa.aboutCheckedProduct'
                                      : 'portal.mfa.aboutChecked') +
      '</p></div>';
  }

  /**
   * The page's body.
   *
   * @param view - `GET /account-api/mfa`'s answer
   * @param ctx - the render context
   * @returns the HTML
   */
  static render(view: Json, ctx: Json): string {
    const t = ctx.t;
    return MfaPages.enrolledCard(view, t) + MfaPages.setupCard(view, t) +
      MfaPages.startCard(view, t) + MfaPages.emailFactorCard(view, t) +
      MfaPages.codesCard(view, t) + MfaPages.aboutCard(view, t);
  }

  /**
   * The pages, for `web_portal_pages.ts`.
   */
  static readonly PAGES: PortalPage[] = [
    { path: PATH, operation: '/account-api/mfa', render: MfaPages.render }
  ];
}

export = MfaPages;
