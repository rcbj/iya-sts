// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_protocol_settings.ts
//
// ---------------------------------------------------------------------------
// THE GENERATED SETTINGS PAGES, DRAWN FROM THEIR VIEWS ALONE (#446,
// 2026-10-05).
//
// Thirteen console pages are rows of `PROTOCOL_SETTINGS_PAGES` in
// `admin-ui/admin.ts` — a lead, warnings, an optional status block, the
// settings forms and a row of links — and one function drew them all. This
// is that function, drawing from what `GET /admin-api/<page>-settings` (and
// `?format=json`) answers: `leadHtml` and `alsoHtml`, which the view carries
// beside their plain text since #446, the settings block and the links.
//
// A STATUS BLOCK (persistence, the cluster, Kerberos pre-authentication and
// the three second-factor mechanisms) is still drawn by the console and
// handed in as `statusHtml`; the page table lists only the pages without
// one until each block is converted.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// ---------------------------------------------------------------------------

import kit = require('./web_kit');
import SettingsForms = require('./web_settings');

type Json = any;

/**
 * Draws one of the generated protocol settings pages from its view.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class ProtocolSettingsPage {
  // The status blocks drawn here, by page (#446): a page whose view carries
  // a `status` and has a row here is drawn whole from its view. Each is
  // handed the page's translator (#539).
  static readonly STATUS: Record<string, (info: Json, t: Json) => string> = {
    '/admin/persistence': function (info: Json, t: Json): string {
      return ProtocolSettingsPage.persistenceStatus(info, t);
    },
    '/admin/kerberos': function (info: Json, t: Json): string {
      return ProtocolSettingsPage.kerberosPreauthStatus(info, t);
    },
    '/admin/webauthn': function (info: Json, t: Json): string {
      return ProtocolSettingsPage.webauthnStatus(info, t);
    },
    '/admin/backup-codes': function (info: Json, t: Json): string {
      return ProtocolSettingsPage.backupCodesStatus(info, t);
    },
    '/admin/totp': function (info: Json, t: Json): string {
      return ProtocolSettingsPage.totpStatus(info, t);
    }
  };

  // THE TRANSLATOR A STATUS BLOCK DRAWS WITH (#539). A NUMBER goes into a
  // message as a parameter; a STRING from the view stays outside it and
  // goes through `kit.esc()`, because a message escapes `'` as `&#39;` and
  // `kit.esc()` as `&apos;`, and the English must not change by a byte.
  // The server-rendered console (`admin.ts`) still calls the blocks with the
  // JSON alone, so a block given no translator takes the default one —
  // English in node.
  /**
   * Answers the translator a status block was given, or the default.
   *
   * @param given - the translator passed in, if any
   * @returns a translator
   */
  static translator(given?: Json): Json {
    return given || kit.context().t;
  }

  // The head of every What / Answer table a status block draws (#539: its
  // two words translated once, here).
  /**
   * Opens a What / Answer key table.
   *
   * @param t - the page's translator
   * @returns the table's opening markup and header row
   */
  static keyHead(t: Json): string {
    return '<table class="key"><tr><th>' +
      t.html('consoleProtocolSettings.thWhat') + '</th><th>' +
      t.html('consoleProtocolSettings.thAnswer') + '</th></tr>';
  }

  // The page, written once. The settings block is the whole of the second
  // half; everything above it is the row.
  /**
   * Draws a protocol settings page: its prose, its status block when it has
   * one, its settings forms and a row of links.
   *
   * @param view - the page's JSON (`page`, `leadHtml`, `alsoHtml`,
   *   `settings`, `links`)
   * @param ctx - the render context (`WebKit.context()`); unused, taken for
   *   the page table's shape
   * @param statusHtml - optional; the status block, drawn by the console
   *   for a block not converted yet; otherwise it is drawn here from the
   *   view's `status` (`STATUS`)
   * @returns the page body as HTML
   */
  static render(view: Json, ctx?: Json, statusHtml?: string): string {
    const t = ProtocolSettingsPage.translator(ctx && ctx.t);
    return kit.note(view.leadHtml) +
      (view.alsoHtml || []).map(function (text) { return kit.warn(text); })
        .join('') +
      // ABOVE the settings forms, deliberately: what the store is doing right
      // now is what somebody came to this page to find out, and the settings
      // that produced it are the answer to the follow-up question. See the
      // `status` member in protocolSettingsJson().
      (statusHtml || (view.status && ProtocolSettingsPage.STATUS[view.page]
        ? ProtocolSettingsPage.STATUS[view.page](view.status, t) : '')) +
      SettingsForms.forms(view.settings, view.page, undefined, t) +
      // A `<p class="sub">` AND NOT A `note()`, which is the rule bullet()
      // states for a list item that opens with a link, applied one helper
      // across. A row of links is longer than a line and note() would
      // therefore FOLD it — and the summary of that fold is a truncation of
      // the first two link texts, so the only controls in the row end up
      // behind a summary made of their own words. Every other link row in
      // this console is a `<p class="sub">` for the same reason.
      '<p class="sub">' + (view.links || []).map(function (link) {
        return '<a href="' + kit.esc(link.href) + '">' + kit.esc(link.what) +
               '</a>';
      }).concat(['<a href="' + kit.esc(view.page) +
                 '?format=json">' +
                 t.html('consoleProtocolSettings.asJson') + '</a>',
                 '<a href="/admin/sts-metadata">' +
                 t.html('consoleProtocolSettings.everyEndpoint') +
                 '</a>']).join(' &middot; ') + '</p>';
  }

  // The /admin/totp status block (#446): what the console drew from its JSON.
  /**
   * Draws the status block of /admin/totp from its JSON.
   *
   * @param info - the block's JSON, the page view's `status`
   * @param tr - optional; the page's translator (#539)
   * @returns the block as HTML
   */
  static totpStatus(info: Json, tr?: Json): string {
    const t = ProtocolSettingsPage.translator(tr);
    const algorithmRows = info.algorithms.map(function (alg) {
      return '<tr><td><code>' + kit.esc(alg.name) + '</code></td>' +
        '<td>' + (alg.inUse
          ? '<span class="state-valid">' +
            t.html('consoleProtocolSettings.inUse') + '</span>'
          : '<span class="state-none">' +
            t.html('consoleProtocolSettings.available') + '</span>') +
        '</td>' +
        '<td>' + kit.esc(alg.note || '') + '</td></tr>';
    }).join('');
    // The two links are markup a message cannot carry (#539): the warning is
    // split around them.
    const html = '<h2>' + t.html('consoleProtocolSettings.totpHeading') +
      '</h2>' +
      (info.offered
        ? ''
        : kit.warn(t.html('consoleProtocolSettings.totpOff1') +
          '<a href="/admin/policies#authn">' +
          t.html('consoleProtocolSettings.policiesLink') + '</a>' +
          t.html('consoleProtocolSettings.totpOff2') +
          '<a href="/admin/users">' +
          t.html('consoleProtocolSettings.usersLink') + '</a>' +
          t.html('consoleProtocolSettings.period'))) +
      ProtocolSettingsPage.keyHead(t) +
      '<tr><th>' + t.html('consoleProtocolSettings.thCode') + '</th><td>' +
      t.html('consoleProtocolSettings.totpCode',
             { digits: String(info.digits), period: String(info.period) }) +
      '</td></tr><tr><th>' + t.html('consoleProtocolSettings.thSkew') +
      '</th><td>' +
      t.html('consoleProtocolSettings.totpSkew',
             { window: String(info.window),
               life: String(info.period * (1 + 2 * info.window)) }) +
      '</td></tr>' +
      '<tr><th>' + t.html('consoleProtocolSettings.thSecret') + '</th><td>' +
      t.html('consoleProtocolSettings.totpSecret',
             { bits: String(info.secretBits) }) + kit.esc(info.encoding) +
      '</td></tr>' +
      '<tr><th>' + t.html('consoleProtocolSettings.thTruncation') +
      '</th><td>' + kit.esc(info.truncation) + '</td></tr>' +
      '</table>' +
      '<h3>' + t.html('consoleProtocolSettings.digestsHeading') + '</h3>' +
      '<table><tr><th>' + t.html('consoleProtocolSettings.thAlgorithm') +
      '</th><th>' + t.html('consoleProtocolSettings.thState') + '</th><th>' +
      t.html('consoleProtocolSettings.thNote') + '</th></tr>' +
      algorithmRows + '</table>';
    return html;
  }

  // The /admin/backup-codes status block (#446): what the console drew from its
  // JSON.
  /**
   * Draws the status block of /admin/backup-codes from its JSON.
   *
   * @param info - the block's JSON, the page view's `status`
   * @param tr - optional; the page's translator (#539)
   * @returns the block as HTML
   */
  static backupCodesStatus(info: Json, tr?: Json): string {
    const t = ProtocolSettingsPage.translator(tr);
    // The links are markup a message cannot carry (#539), so the prose is
    // split around each one; the view's own strings stay outside messages.
    const html =
      '<h3>' + t.html('consoleProtocolSettings.bcHeading') + '</h3>' +
      ProtocolSettingsPage.keyHead(t) +
      '<tr><th>' + t.html('consoleProtocolSettings.thOffered') + '</th><td>' +
      (info.offered
        ? '<span class="state-valid">' +
          t.html('consoleProtocolSettings.yes') + '</span>' +
          t.html('consoleProtocolSettings.bcOfferedYes')
        : '<span class="state-none">' +
          t.html('consoleProtocolSettings.no') + '</span>' +
          t.html('consoleProtocolSettings.bcOfferedNo')) +
        '</td></tr>' +
      '<tr><th>' + t.html('consoleProtocolSettings.thSet') + '</th><td>' +
      t.html('consoleProtocolSettings.bcSet',
             { count: String(info.count), length: String(info.length),
               group: String(info.groupSize || 0) }) + '</td></tr>' +
      '<tr><th>' + t.html('consoleProtocolSettings.thStrength') +
      '</th><td>' +
      t.html('consoleProtocolSettings.bcStrength',
             { bits: String(info.bitsPerCode),
               alphabet: String(info.alphabetSize) }) +
      '</td></tr><tr><th>' + t.html('consoleProtocolSettings.thAlphabet') +
      '</th><td><code>' +
      kit.esc(info.alphabet) + '</code>' +
      t.html('consoleProtocolSettings.bcAlphabet1') + '<strong>' +
      t.html('consoleProtocolSettings.bcNotShared') +
      '<a href="/admin/totp">TOTP</a></strong>' +
      t.html('consoleProtocolSettings.bcAlphabet2') +
      '</td></tr><tr><th>' + t.html('consoleProtocolSettings.thGenerated') +
      '</th><td>' +
        kit.esc(info.source) +
      '</td></tr><tr><th>' + t.html('consoleProtocolSettings.thCompared') +
      '</th><td>' + kit.esc(info.comparison) + ' ' +
      t.html('consoleProtocolSettings.bcCompared') + '</td></tr><tr><th>' +
      t.html('consoleProtocolSettings.thAtRest') + '</th><td>' +
      kit.esc(info.atRest) + '</td></tr>' +
      '</table>' +
      '<h3>' + t.html('consoleProtocolSettings.bcWillNotHeading') + '</h3>' +
      kit.note(t.html('consoleProtocolSettings.bcNoteRequest')) +
      kit.note(t.html('consoleProtocolSettings.bcNoteOnce1') + '<a ' +
      'href="/admin/users">' + t.html('consoleProtocolSettings.usersLink') +
      '</a>' + t.html('consoleProtocolSettings.bcNoteOnce2')) +
      kit.note(t.html('consoleProtocolSettings.bcNoteNeverShown')) +
      kit.note(t.html('consoleProtocolSettings.bcNoteNotFirst'));
    return html;
  }

  // The /admin/webauthn status block (#446): what the console drew from its
  // JSON.
  /**
   * Draws the status block of /admin/webauthn from its JSON.
   *
   * @param info - the block's JSON, the page view's `status`
   * @param tr - optional; the page's translator (#539)
   * @returns the block as HTML
   */
  static webauthnStatus(info: Json, tr?: Json): string {
    const t = ProtocolSettingsPage.translator(tr);
    const state = function (cls: string, words: string): string {
      return '<span class="' + cls + '">' + words + '</span>';
    };
    const algorithmRows = info.algorithms.map(function (alg) {
      return '<tr><td><code>' + kit.esc(alg.name) + '</code></td>' +
        '<td class="num"><code>' + kit.esc(String(alg.coseAlg)) +
        '</code></td><td>' + (alg.offered
          ? state('state-valid', t.html('consoleProtocolSettings.offered'))
          : state('state-none',
                  t.html('consoleProtocolSettings.verifiableNotOffered'))) +
        '</td></tr>';
    }).join('');
    // Every link is markup a message cannot carry (#539), so the prose is
    // split around each one; the view's own strings stay outside messages.
    const html = '<h2>' + t.html('consoleProtocolSettings.waHeading') +
      '</h2>' +
      (info.offered
        ? ''
        : kit.warn(t.html('consoleProtocolSettings.waOff') + '<a ' +
          'href="/admin/users">' +
          t.html('consoleProtocolSettings.usersLink') + '</a>' +
          t.html('consoleProtocolSettings.period'))) +
      ProtocolSettingsPage.keyHead(t) +
      '<tr><th>' + t.html('consoleProtocolSettings.thRpId') + '</th><td>' +
        (info.rpId
          ? '<code>' + kit.esc(info.rpId) + '</code>' +
            t.html('consoleProtocolSettings.waRpIdSet')
          : t.html('consoleProtocolSettings.waRpIdDefault')) + '</td></tr>' +
      '<tr><th>' + t.html('consoleProtocolSettings.thRpName') +
      '</th><td><code>' + kit.esc(info.rpName) + '</code>' +
      t.html('consoleProtocolSettings.waRpName') + '</td></tr><tr><th>' +
      t.html('consoleProtocolSettings.thUv') + '</th><td><code>' +
      kit.esc(info.userVerification) +
        '</code> — ' + (info.userVerificationEnforced
          ? t.html('consoleProtocolSettings.waUvEnforced')
          : t.html('consoleProtocolSettings.waUvRequested')) + '</td></tr>' +
      '<tr><th>' + t.html('consoleProtocolSettings.thAttestation') +
      '</th><td><code>' + kit.esc(info.attestation) +
      '</code>' + t.html('consoleProtocolSettings.waConveyance') +
        (info.attestationDemandsTrust && info.attestation !== 'enterprise' &&
         info.attestation !== 'direct'
          ? t.html('consoleProtocolSettings.waSentDirect')
          : '') +
        t.html('consoleProtocolSettings.waAttNext') + '</td></tr>' +
      '<tr><th>' + t.html('consoleProtocolSettings.thTimeout') + '</th><td>' +
      t.html('consoleProtocolSettings.waTimeout',
             { ms: String(info.timeoutMs) }) + '</td></tr><tr><th>' +
      t.html('consoleProtocolSettings.thCounter') + '</th><td>' +
      kit.esc(info.signatureCounter) +
        '</td></tr>' +
      '</table>' +
      ProtocolSettingsPage.attestationPolicyBlock(info, t) +
      '<h3>CTAP</h3>' +
      kit.note(t.html('consoleProtocolSettings.waCtapNote')) +
      ProtocolSettingsPage.keyHead(t) +
      '<tr><th>' + t.html('consoleProtocolSettings.thAttachment') +
      '</th><td>' +
        (info.authenticatorAttachment === 'any'
          ? t.html('consoleProtocolSettings.waAttachAny')
          : '<code>' + kit.esc(info.authenticatorAttachment) + '</code>' +
            t.html('consoleProtocolSettings.waAttachOnly')) +
            '</td></tr>' +
      '<tr><th>' + t.html('consoleProtocolSettings.thDiscoverable') +
      '</th><td><code>' +
      kit.esc(info.residentKey) +
        '</code>' + t.html('consoleProtocolSettings.waResident1') + '<a ' +
        'href="/admin/policies#passkey">' +
        t.html('consoleProtocolSettings.passkeyPolicyLink') + '</a>' +
        t.html('consoleProtocolSettings.waResident2') + '</td></tr>' +
      '<tr><th>credProps</th><td>' + (info.credProps
        ? t.html('consoleProtocolSettings.waCredPropsYes')
        : t.html('consoleProtocolSettings.waCredPropsNo')) +
      '</td></tr></table><h3>' +
      t.html('consoleProtocolSettings.waMayBeHeading') + '</h3>' +
      kit.note(t.html('consoleProtocolSettings.waMayBeNote')) +
      ProtocolSettingsPage.keyHead(t) +
      '<tr><th>' + t.html('consoleProtocolSettings.thPrimary') + '</th><td>' +
      (info.primaryAllowed
        ? state('state-valid', t.html('consoleProtocolSettings.allowed')) +
          t.html('consoleProtocolSettings.waPrimaryYes')
        : state('state-none', t.html('consoleProtocolSettings.notAllowed')) +
          t.html('consoleProtocolSettings.waPrimaryNo')) + '</td></tr>' +
      '<tr><th>' + t.html('consoleProtocolSettings.thNoUsername') +
      '</th><td>' + (info.usernameless &&
                                         info.primaryAllowed
        ? state('state-valid', t.html('consoleProtocolSettings.offered')) +
          t.html('consoleProtocolSettings.waUsernamelessYes')
        : state('state-none', t.html('consoleProtocolSettings.notOffered')) +
          t.html('consoleProtocolSettings.waUsernamelessNo1') +
          '<a href="/admin/policies#passkey">' +
          t.html('consoleProtocolSettings.passkeyPolicyLink') + '</a>' +
          t.html('consoleProtocolSettings.waUsernamelessNo2') +
          (info.primaryAllowed ? ''
            : t.html('consoleProtocolSettings.waNoPrimary')) +
          t.html('consoleProtocolSettings.waUsernamelessNo3')) +
        '</td></tr>' +
      '<tr><th>' + t.html('consoleProtocolSettings.thSecondFactor') +
      '</th><td>' + (info.mfaAllowed
        ? state('state-valid', t.html('consoleProtocolSettings.allowed')) +
          t.html('consoleProtocolSettings.waMfaYes')
        : state('state-none', t.html('consoleProtocolSettings.notAllowed')) +
          t.html('consoleProtocolSettings.waMfaNo') +
          '<a href="/admin/totp">' +
          t.html('consoleProtocolSettings.waAuthApp') + '</a>' +
          t.html('consoleProtocolSettings.period')) + '</td></tr>' +
      '<tr><th>' + t.html('consoleProtocolSettings.thKeysPerPerson') +
      '</th><td>' +
      t.html('consoleProtocolSettings.waKeysPerPerson',
             { n: String(info.maxKeysPerPerson) }) + '</td></tr>' +
      '</table>' +
      '<h3>' + t.html('consoleProtocolSettings.waAlgorithmsHeading') +
      '</h3>' +
      kit.note(t.html('consoleProtocolSettings.waAlgNote')) +
      '<table><tr><th>' + t.html('consoleProtocolSettings.thAlgorithm') +
      '</th><th ' +
      'class="num">COSE</th><th>' + t.html('consoleProtocolSettings.thState') +
      '</th></tr>' +
      algorithmRows + '</table>' +
      '<p class="sub">' + t.html('consoleProtocolSettings.waCurves') +
      info.curves.map(function (curve) {
        return '<code>' + kit.esc(curve.name) + '</code>';
      }).join(', ') + t.html('consoleProtocolSettings.period') + '</p>';
    return html;
  }

  // The attestation half of the /admin/webauthn block, given the page's
  // translator by its caller (#539).
  /**
   * Draws the attestation statement's table of /admin/webauthn.
   *
   * @param info - the block's JSON, the page view's `status`
   * @param tr - optional; the page's translator
   * @returns the table as HTML
   */
  static attestationPolicyBlock(info, tr?: Json) {
    const t = ProtocolSettingsPage.translator(tr);
    const mds = info.mds;
    const policyText = {
      off: t.html('consoleProtocolSettings.attPolicyOff'),
      'verify-if-present': t.html('consoleProtocolSettings.attPolicyVerify'),
      'require-trusted': t.html('consoleProtocolSettings.attPolicyRequire')
    };
    const html = '<h3>' + t.html('consoleProtocolSettings.attHeading') +
      '</h3>' +
      ProtocolSettingsPage.keyHead(t) +
      '<tr><th>' + t.html('consoleProtocolSettings.thPolicy') +
      '</th><td><code>' + kit.esc(info.attestationPolicy) +
        '</code>' + (info.attestationPolicyConfigured === 'by-mode'
          ? ' (<code>by-mode</code>)' : '') + ' — ' +
        (policyText[info.attestationPolicy] || '') +
        (info.attestationDemandsTrust &&
         info.attestationPolicy !== 'require-trusted'
          ? t.html('consoleProtocolSettings.attTrustAnyway')
          : '') + '</td></tr>' +
      '<tr><th>' + t.html('consoleProtocolSettings.thFormats') + '</th><td>' +
        info.attestationFormats.map((f) => {
          return '<code>' + kit.esc(f) + '</code>';
        }).join(', ') + t.html('consoleProtocolSettings.attFormats') +
        '</td></tr>' +
      '<tr><th>' + t.html('consoleProtocolSettings.thAnchors') + '</th><td>' +
        t.html('consoleProtocolSettings.attAnchors',
               { n: String(info.attestationTrustAnchors) }) + '</td></tr>' +
      '<tr><th>FIDO Metadata Service</th><td>' +
        (!mds || !mds.known
          ? t.html('consoleProtocolSettings.attMdsUnknown')
          : (mds.active
              ? t.html('consoleProtocolSettings.attMdsBlob1') + '<code>' +
                kit.esc(String(mds.serial)) + '</code>' +
                t.html('consoleProtocolSettings.attMdsBlob2',
                       { rows: String(mds.rows) }) +
                (mds.nextUpdateAt
                  ? kit.esc(new Date(mds.nextUpdateAt).toISOString()
                    .slice(0, 10))
                  : t.html('consoleProtocolSettings.attUnstated')) +
                (mds.stale ? t.html('consoleProtocolSettings.attMdsStale')
                  : '')
              : t.html('consoleProtocolSettings.attMdsNone')) +
            ' ' + (mds.url
              ? t.html('consoleProtocolSettings.attMdsFrom') + '<code>' +
                kit.esc(mds.url) + '</code>' +
                t.html('consoleProtocolSettings.attMdsBy') + '<code>' +
                kit.esc(mds.job) + '</code>' +
                t.html('consoleProtocolSettings.attMdsJob')
              : t.html('consoleProtocolSettings.attMdsUploaded') +
                '<a href="/admin/risk">' +
                t.html('consoleProtocolSettings.riskLink') + '</a>' +
                t.html('consoleProtocolSettings.attMdsEmpty'))) +
        '</td></tr>' +
      '<tr><th>' + t.html('consoleProtocolSettings.thAllowedModels') +
      '</th><td>' +
        (info.attestationAllowedAaguids.length
          ? info.attestationAllowedAaguids.map((a) => {
            return '<code>' + kit.esc(a) + '</code>';
          }).join(', ')
          : t.html('consoleProtocolSettings.attAnyModel')) + '</td></tr>' +
      '<tr><th>' + t.html('consoleProtocolSettings.thCertification') +
      '</th><td>' + t.html('consoleProtocolSettings.attAtLeast') + '<code>' +
        kit.esc(info.attestationMinCertificationLevel) + '</code>' +
        (info.attestationRequireFips
          ? t.html('consoleProtocolSettings.attFips') : '') +
        '</td></tr>' +
      '<tr><th>android-safetynet</th><td>' +
        (info.attestationAllowSafetynet
          ? t.html('consoleProtocolSettings.attSafetynetYes')
          : t.html('consoleProtocolSettings.attSafetynetNo')) + '</td></tr>' +
      '<tr><th>android-key</th><td>' +
        (info.attestationAndroidSoftwareKeys
          ? t.html('consoleProtocolSettings.attAndroidSoftware')
          : t.html('consoleProtocolSettings.attAndroidHardware')) +
        '</td></tr>' +
      '</table>' +
      kit.note(t.html('consoleProtocolSettings.attNote1') + '<a ' +
      'href="/admin/users">' + t.html('consoleProtocolSettings.usersLink') +
      '</a>' + t.html('consoleProtocolSettings.attNote2'));
    return html;
  }

  // The /admin/kerberos status block (#446): what the console drew from its
  // JSON.
  /**
   * Draws the status block of /admin/kerberos from its JSON.
   *
   * @param info - the block's JSON, the page view's `status`
   * @param tr - optional; the page's translator (#539)
   * @returns the block as HTML
   */
  static kerberosPreauthStatus(info: Json, tr?: Json): string {
    const t = ProtocolSettingsPage.translator(tr);
    const row = (what: string, answer: string) => {
      return '<tr><th>' + kit.esc(what) + '</th><td>' + answer + '</td></tr>';
    };
    const state = function (cls: string, words: string): string {
      return '<span class="' + cls + '">' + words + '</span>';
    };
    // The view's own strings stay outside the messages (#539): see
    // `translator()`.
    const krbtgtHtml = !info.krbtgt ? '' :
      '<h3>' + t.html('consoleProtocolSettings.krbHeading') + '</h3>' +
      ProtocolSettingsPage.keyHead(t) +
      row(t.text('consoleProtocolSettings.thKeyFrom'),
        info.krbtgt.source === 'stored'
        ? t.html('consoleProtocolSettings.krbFromStored')
        : info.krbtgt.source === 'password'
          ? t.html('consoleProtocolSettings.krbFromPassword')
          : info.krbtgt.source === 'unreadable'
            ? t.html('consoleProtocolSettings.krbFromUnreadable')
            : t.html('consoleProtocolSettings.krbFromNothing')) +
      row('kvno',
        kit.esc(info.krbtgt.kvno == null ? '—' : String(info.krbtgt.kvno))) +
      row(t.text('consoleProtocolSettings.thLastRotated'),
          info.krbtgt.lastRotatedAt ? kit.esc(info.krbtgt.lastRotatedAt)
            : t.html('consoleProtocolSettings.never')) +
      row(t.text('consoleProtocolSettings.thNextRotation'),
        info.krbtgt.scheduled
        ? kit.esc(String(info.krbtgt.nextDueAt || '—'))
        : t.html('consoleProtocolSettings.krbNoneDash') +
          kit.esc(String(info.krbtgt.offReason || ''))) +
      row(t.text('consoleProtocolSettings.thPreviousKept'),
        (info.krbtgt.retained || [])
        .map(function (one: any) {
          return 'kvno ' + kit.esc(String(one.kvno)) +
            t.html('consoleProtocolSettings.krbUntil') +
            kit.esc(String(one.expiresAt));
        }).join('; ') || t.html('consoleProtocolSettings.none')) +
      '</table>' +
      '<p><a href="/admin/kerberos/principals">' +
      t.html('consoleProtocolSettings.krbRotateLink') + '</a></p>';
    // PKINIT (#179): a certificate as the pre-authentication, and anonymous
    // PKINIT as FAST armor — `kerberos/krb5_pkinit.ts`'s policy().
    const pkinit = info.pkinit;
    const pkinitHtml = !pkinit ? '' :
      '<h3>' + t.html('consoleProtocolSettings.pkHeading') + '</h3>' +
      ProtocolSettingsPage.keyHead(t) +
      row('PKINIT (RFC 4556)', pkinit.pkinit
        ? state('state-valid', t.html('consoleProtocolSettings.on')) +
          ' — ' + kit.esc(pkinit.clientCertificates)
        : state('state-none', t.html('consoleProtocolSettings.off')) +
          ' (<code>krb5.pkinit</code>)') +
      row(t.text('consoleProtocolSettings.thKeyAgreement'),
          kit.esc((pkinit.keyAgreement || []).join(', ')) +
          t.html('consoleProtocolSettings.pkRsa') +
          kit.esc(pkinit.rsaKeyTransport)) +
      row(t.text('consoleProtocolSettings.thReplyKey'),
          kit.esc((pkinit.kdfs || []).join(', ')) +
          (pkinit.legacyKdf
            ? t.html('consoleProtocolSettings.pkLegacyAccepted')
            : t.html('consoleProtocolSettings.pkLegacyRefused'))) +
      row(t.text('consoleProtocolSettings.thFreshness'),
          pkinit.freshnessRequired
        ? t.html('consoleProtocolSettings.pkRequired')
        : t.html('consoleProtocolSettings.pkAcceptedNotRequired')) +
      row(t.text('consoleProtocolSettings.thKdcCert'), pkinit.kdcCertificate
        ? kit.esc(pkinit.kdcCertificate.keyAlg) +
          t.html('consoleProtocolSettings.pkSerial') +
          kit.esc(pkinit.kdcCertificate.serialHex) +
          t.html('consoleProtocolSettings.pkExpires') +
          kit.esc(pkinit.kdcCertificate.notAfter) +
          t.html('consoleProtocolSettings.pkFromCa') +
          '<a href="/admin/pki">PKI</a>' +
          t.html('consoleProtocolSettings.pkClientsTrust')
        : t.html('consoleProtocolSettings.pkNoCert') +
          kit.esc(pkinit.kdcKeyAlgorithm)) +
      row(t.text('consoleProtocolSettings.thTicketSays'),
          t.html('consoleProtocolSettings.pkTicketSays')) +
      row(t.text('consoleProtocolSettings.thAnonymous'),
          pkinit.anonymousPkinit
        ? state('state-valid', t.html('consoleProtocolSettings.on')) +
          ' — ' + kit.esc(pkinit.anonymousTickets) +
          t.html('consoleProtocolSettings.pkKinitThen')
        : state('state-none', t.html('consoleProtocolSettings.off')) + ' ' +
          '(<code>krb5.anonymousPkinit</code>)') +
      row(t.text('consoleProtocolSettings.thPostQuantum'),
          kit.esc(pkinit.postQuantum)) +
      '</table>';
    const html =
      '<h3>' + t.html('consoleProtocolSettings.krbPreauthHeading') + '</h3>' +
      ProtocolSettingsPage.keyHead(t) +
      row(t.text('consoleProtocolSettings.thPasswordAlone'),
          info.passwordAloneRefused
            ? state('state-valid',
                    t.html('consoleProtocolSettings.refused')) +
              t.html('consoleProtocolSettings.krbPasswordRefused')
            : state('state-none',
                    t.html('consoleProtocolSettings.accepted')) +
              t.html('consoleProtocolSettings.krbPasswordAccepted')) +
      row('FAST (RFC 6113)', info.fast
        ? state('state-valid', t.html('consoleProtocolSettings.yes')) +
          t.html('consoleProtocolSettings.krbFastYes') +
          '<a href="/admin/kerberos/principals">' +
          t.html('consoleProtocolSettings.principalsLink') + '</a>)'
        : state('state-none', t.html('consoleProtocolSettings.no')) +
          ' — ' + kit.esc(info.note)) +
      row(t.text('consoleProtocolSettings.thSecondFactorKrb'), info.fast
        ? t.html('consoleProtocolSettings.krbOtp')
        : t.html('consoleProtocolSettings.none')) +
      row(t.text('consoleProtocolSettings.thTicketSays'), info.fast
        ? t.html('consoleProtocolSettings.krbIndicator1') + '<code>' +
          kit.esc(info.otpIndicator || 'otp') + '</code>' +
          t.html('consoleProtocolSettings.krbIndicator2')
        : '—') +
      '</table>' + pkinitHtml + krbtgtHtml;
    return html;
  }

  // The /admin/persistence status block (#446): what the console drew from its
  // JSON.
  /**
   * Draws the status block of /admin/persistence from its JSON.
   *
   * @param info - the block's JSON, the page view's `status`
   * @param tr - optional; the page's translator (#539)
   * @returns the block as HTML
   */
  static persistenceStatus(info: Json, tr?: Json): string {
    const t = ProtocolSettingsPage.translator(tr);
    const off = info.mode === 'memory';
    // Every row's words are messages (#539); the view's own strings stay
    // outside them (`translator()`), and so does markup a message cannot
    // carry — a link, a `<strong class="bad">`.
    const gap = t.html('consoleProtocolSettings.sentenceGap');
    const period = t.html('consoleProtocolSettings.period');

    const rows = [
      [t.text('consoleProtocolSettings.thMode'), off
        ? t.html('consoleProtocolSettings.perModeMemory')
        : '<strong>' + kit.esc(info.mode) + '</strong>' +
          (info.configuredMode !== info.mode
            ? t.html('consoleProtocolSettings.perFellBack1') + '<code>' +
              kit.esc(info.configuredMode) + '</code>' +
              t.html('consoleProtocolSettings.perFellBack2')
            : '')],
      [t.text('consoleProtocolSettings.thWhere'), off
        ? t.html('consoleProtocolSettings.perNowhere')
        : info.mode === 'ldif'
          ? '<code>' + kit.esc(info.dataDir || '') + '</code>' +
            t.html('consoleProtocolSettings.perLdif')
          : info.database
            ? 'PostgreSQL <code>' + kit.esc(String(info.database.host)) + ':' +
              kit.esc(String(info.database.port)) + '/' +
              kit.esc(String(info.database.database)) + '</code>' +
              t.html('consoleProtocolSettings.perAs') + '<code>' +
              kit.esc(String(info.database.user ||
                t.text('consoleProtocolSettings.perConnUser'))) +
              '</code>' + t.html('consoleProtocolSettings.perNeverShown')
            : t.html('consoleProtocolSettings.perConnString')],
      // WHERE THE PASSWORD COMES FROM (2026-09-12), as its own row and never
      // the password itself. A deployment that moved it into a secret store has
      // no other way to see that this process agreed: the row above looks
      // identical either way, because it never printed the password.
      [t.text('consoleProtocolSettings.thPassword'),
        off || info.mode !== 'postgres'
        ? t.html('consoleProtocolSettings.perNoCred')
        : (info.database
            ? (info.database.passwordProvider &&
               info.database.passwordProvider !== 'none'
                ? '<strong>' + kit.esc(String(info.database.passwordFrom)) +
                  '</strong>' + t.html('consoleProtocolSettings.perPwdFrom') +
                  '<a href="/admin/encryption">' +
                  t.html('consoleProtocolSettings.perEncLink') + '</a>' +
                  period
                : t.html('consoleProtocolSettings.perPwdPlain'))
            : t.html('consoleProtocolSettings.unknown'))],
      // TLS TO THE DATABASE, as its own row rather than folded into the one
      // above. Encryption and authentication are two answers and this page has
      // room to give both — which matters here more than in most places,
      // because the honest state of the compose stack is "encrypted and not
      // authenticated" and a single tick would have to round that one way or
      // the other.
      [t.text('consoleProtocolSettings.thTransport'),
        off || info.mode !== 'postgres'
        ? (info.mode === 'ldif'
            ? t.html('consoleProtocolSettings.perTransportFile')
            : t.html('consoleProtocolSettings.perTransportNone'))
        : (info.database
            ? (info.database.encrypted
                ? '<strong>TLS</strong> &mdash; ' +
                  kit.esc(String(info.database.tls))
                : '<strong class="bad">' +
                  t.html('consoleProtocolSettings.perNotTls') +
                  '</strong> &mdash; ' +
                  kit.esc(String(info.database.tls)))
            : t.html('consoleProtocolSettings.unknown'))],
      [t.text('consoleProtocolSettings.thWritten'), off
        ? t.html('consoleProtocolSettings.perNothing') : [
          info.persistsDirectory
            ? t.html('consoleProtocolSettings.perWDirectory') : null,
          info.persistsRealms
            ? t.html('consoleProtocolSettings.perWRealms') : null,
          info.persistsAppconfig
            ? t.html('consoleProtocolSettings.perWAppconfig') : null,
          info.minted && info.minted.persisting
            ? t.html('consoleProtocolSettings.perWMinted',
                     { stores: String(info.minted.stores) })
            : null
        ].filter(Boolean).join(', ')],
      // -----------------------------------------------------------------------
      // THE NEGATIVE ROW, AND IT IS NOW CONDITIONAL — which is the whole of
      // what changed here on 2026-09-06. It used to be a constant, because the
      // answer used to be the same in every configuration. Keeping it as a row
      // rather than deleting it is deliberate: "what is never written" is the
      // question an operator actually has, and a page that answered it only
      // when the answer was long would be a page that stopped answering it
      // exactly when the answer got interesting.
      // -----------------------------------------------------------------------
      [t.text('consoleProtocolSettings.thNeverWritten'), off
        ? t.html('consoleProtocolSettings.perNeverAll')
        : (info.minted && info.minted.persisting
            ? t.html('consoleProtocolSettings.perNeverMinted')
            : t.html('consoleProtocolSettings.perNeverList') +
              (info.minted && info.minted.unsupportedReason
                ? t.html('consoleProtocolSettings.perBecause') +
                  kit.esc(info.minted.unsupportedReason)
                : t.html('consoleProtocolSettings.perBecauseDev')) + period)],
      // -----------------------------------------------------------------------
      // AND WHETHER THIS PROCESS IS ALONE WITH ITS COPY. This row is the
      // reversal of the sentence that used to be two paragraphs of prose above:
      // "one process per database".
      // -----------------------------------------------------------------------
      [t.text('consoleProtocolSettings.thOtherProcesses'),
        off || !info.replication
        ? '—'
        : info.replication.coordinating
          ? t.html('consoleProtocolSettings.perCoord',
                   { seq: String(info.replication.appliedSeq),
                     rows: String(info.replication.rowsApplied),
                     others: String(info.replication.otherProcesses),
                     ms: String(info.replication.pollIntervalMs) }) +
            (info.replication.lastError
              ? gap + '<strong class="bad">' +
                t.html('consoleProtocolSettings.perPullFailed') +
                '</strong> — ' + kit.esc(info.replication.lastError) +
                t.html('consoleProtocolSettings.perBehind')
              : period)
          : t.html('consoleProtocolSettings.perNotCoord') +
            (info.replication.supported
              ? t.html('consoleProtocolSettings.perSetCoordinate')
              : t.html('consoleProtocolSettings.perCannot1') +
                kit.esc(info.mode) +
                t.html('consoleProtocolSettings.perCannot2'))],
      [t.text('consoleProtocolSettings.thWhen'), off ? '—'
        : info.writeDelayMs === 0
          ? t.html('consoleProtocolSettings.perImmediate')
          : t.html('consoleProtocolSettings.perDelay',
                   { ms: String(info.writeDelayMs) })],
      [t.text('consoleProtocolSettings.thHealth'), off ? '—'
        : info.lastError
          ? t.html('consoleProtocolSettings.perLastWriteFailed') +
            kit.esc(info.lastError) +
            t.html('consoleProtocolSettings.perReadsAnswered') +
            (info.retryArmed ? t.html('consoleProtocolSettings.perRetryArmed')
              : '') + gap + (info.answersAfterCommit
              ? t.html('consoleProtocolSettings.per503')
              : t.html('consoleProtocolSettings.perAnsweredBefore'))
          : t.html('consoleProtocolSettings.perWritingNormally')],
      // ANSWER AFTER COMMIT AND THE EVENT LOOP (#351): what
      // persistence.status() carries for them, drawn so an operator does not
      // need the API to see a refused write waiting or a blocked loop.
      [t.text('consoleProtocolSettings.thAnsweredAfterCommit'), off ? '—'
        : (info.answersAfterCommit
          ? t.html('consoleProtocolSettings.perAacYes')
          : t.html('consoleProtocolSettings.perAacNo')) +
          (info.commitBacklog
            ? gap + '<strong class="bad">' +
              t.html('consoleProtocolSettings.perRefusedWaiting') +
              '</strong>' + t.html('consoleProtocolSettings.perHeld')
            : period)],
      [t.text('consoleProtocolSettings.thEventLoop'), !info.eventLoop ? '—'
        : t.html('consoleProtocolSettings.perWorst',
                 { max: String((info.eventLoop.sinceReport || {}).maxMs) }) +
          (info.eventLoop.lastReport
            ? t.html('consoleProtocolSettings.perWindow',
                     { max: String(info.eventLoop.lastReport.maxMs) })
            : '') +
          t.html('consoleProtocolSettings.perWarnOver',
                 { ms: String(info.eventLoop.warnAboveMs) })],
      [t.text('consoleProtocolSettings.thWrittenSoFar'), off ? '—'
        : t.html('consoleProtocolSettings.perWrittenSoFar',
                 { writes: String(info.writes),
                   failures: String(info.failures),
                   entries: String(info.entriesTracked),
                   realms: String(info.realmsTracked) }) +
          (info.lastWriteAt ? kit.esc(info.lastWriteAt)
            : t.html('consoleProtocolSettings.perNotYet')) +
          (info.pending ? t.html('consoleProtocolSettings.perPendingChange')
            : period)],
      [t.text('consoleProtocolSettings.thRestored'), off ? '—'
        : info.restoredAt
          ? t.html('consoleProtocolSettings.perRestored',
                   { entries: String(info.restored.entries),
                     realms: String(info.restored.realms),
                     overrides: String(info.restored.overrides) }) +
            kit.esc(info.restoredAt) +
            t.html('consoleProtocolSettings.perRestoredZero')
          : t.html('consoleProtocolSettings.perNothingRestored')],
      [t.text('consoleProtocolSettings.thCoordination'),
        t.html('consoleProtocolSettings.perNo') + kit.esc(info.note)]
    ];

    const html = '<h2>' + t.html('consoleProtocolSettings.perRightNow') +
      '</h2>' +
      (off
        ? kit.note(t.html('consoleProtocolSettings.perOffNote'))
        : (info.lastError
            ? kit.warn(t.html('consoleProtocolSettings.perNotAccepting'))
            : '')) +
      ProtocolSettingsPage.keyHead(t) +
      rows.map(function (row) {
        return '<tr><th>' + kit.esc(row[0]) + '</th><td>' + row[1] +
               '</td></tr>';
      }).join('') +
      '</table>';

    return html;
  }
}

export = ProtocolSettingsPage;
