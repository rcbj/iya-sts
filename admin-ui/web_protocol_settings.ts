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
  // a `status` and has a row here is drawn whole from its view.
  static readonly STATUS: Record<string, (info: Json) => string> = {
    '/admin/webauthn': function (info: Json): string {
      return ProtocolSettingsPage.webauthnStatus(info);
    },
    '/admin/backup-codes': function (info: Json): string {
      return ProtocolSettingsPage.backupCodesStatus(info);
    },
    '/admin/totp': function (info: Json): string {
      return ProtocolSettingsPage.totpStatus(info);
    }
  };

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
    return kit.note(view.leadHtml) +
      (view.alsoHtml || []).map(function (text) { return kit.warn(text); })
        .join('') +
      // ABOVE the settings forms, deliberately: what the store is doing right
      // now is what somebody came to this page to find out, and the settings
      // that produced it are the answer to the follow-up question. See the
      // `status` member in protocolSettingsJson().
      (statusHtml || (view.status && ProtocolSettingsPage.STATUS[view.page]
        ? ProtocolSettingsPage.STATUS[view.page](view.status) : '')) +
      SettingsForms.forms(view.settings, view.page) +
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
                 '?format=json">this page as ' +
                                               'JSON</a>',
                 '<a href="/admin/sts-metadata">every endpoint this service ' +
                 'registers</a>']).join(' &middot; ') + '</p>';
  }

  // The /admin/totp status block (#446): what the console drew from its JSON.
  /**
   * Draws the status block of /admin/totp from its JSON.
   *
   * @param info - the block's JSON, the page view's `status`
   * @returns the block as HTML
   */
  static totpStatus(info: Json): string {
    const algorithmRows = info.algorithms.map(function (alg) {
      return '<tr><td><code>' + kit.esc(alg.name) + '</code></td>' +
        '<td>' + (alg.inUse
          ? '<span class="state-valid">in use</span>'
          : '<span class="state-none">available</span>') + '</td>' +
        '<td>' + kit.esc(alg.note || '') + '</td></tr>';
    }).join('');
    const html = '<h2>The mechanism</h2>' +
      (info.offered
        ? ''
        : kit.warn('<strong>The authentication policy turns authenticator ' +
          'apps off</strong> (<a href="/admin/policies#authn">Policies</a>), ' +
          'so ' +
          'nobody new can enrol an authenticator app. <strong>It does not ' +
          'disable a secret somebody already holds</strong> — that account ' +
          'is still configured for two factors and the sign-in screen still ' +
          'asks for the code, because a switch that silently downgraded it ' +
          'would be a security control whose off position does something ' +
          'other than what it says. Clearing an existing enrolment is on ' +
          'that person\'s row under <a href="/admin/users">Users</a>.')) +
      '<table class="key"><tr><th>What</th><th>Answer</th></tr>' +
      '<tr><th>Code</th><td>' + kit.esc(String(info.digits)) + ' digits, a ' +
        'new one every ' + kit.esc(String(info.period)) + ' ' +
      'seconds</td></tr><tr><th>Skew forgiven</th><td>' +
      kit.esc(String(info.window)) + ' step(s) ' +
        'either side, so a code lives about ' +
        kit.esc(String(info.period * (1 + 2 * info.window))) + ' seconds. ' +
        '<strong>This one applies to everybody</strong>, existing enrolments ' +
        'included.</td></tr>' +
      '<tr><th>Shared secret</th><td>' + kit.esc(String(info.secretBits)) +
      ' bits, ' +
        kit.esc(info.encoding) + '</td></tr>' +
      '<tr><th>Truncation</th><td>' + kit.esc(info.truncation) + '</td></tr>' +
      '</table>' +
      '<h3>Digests</h3>' +
      '<table><tr><th>Algorithm</th><th>State</th><th>Note</th></tr>' +
      algorithmRows + '</table>';
    return html;
  }

  // The /admin/backup-codes status block (#446): what the console drew from its
  // JSON.
  /**
   * Draws the status block of /admin/backup-codes from its JSON.
   *
   * @param info - the block's JSON, the page view's `status`
   * @returns the block as HTML
   */
  static backupCodesStatus(info: Json): string {
    const html =
      '<h3>What a code is</h3>' +
      '<table class="key"><tr><th>What</th><th>Answer</th></tr>' +
      '<tr><th>Offered</th><td>' + (info.offered
        ? '<span class="state-valid">yes</span> — a set is issued the first ' +
          'time somebody enrols a second factor.'
        : '<span class="state-none">no</span> — no NEW set will be issued. ' +
          '<strong>A set already issued goes on working</strong>, which is ' +
          'the contract the authentication policy\'s TOTP row and ' +
          '<code>webauthn.enabled</code> both keep: a switch that took away ' +
          'the only way back into an account whose phone is lost would be ' +
          'the worst one on this console.') +
        '</td></tr>' +
      '<tr><th>Set</th><td>' + kit.esc(String(info.count)) + ' codes of ' +
        kit.esc(String(info.length)) + ' characters, printed in groups of ' +
        kit.esc(String(info.groupSize || 0)) + '.</td></tr>' +
      '<tr><th>Strength</th><td><strong>' + kit.esc(String(info.bitsPerCode)) +
        ' bits</strong> per code, out of an alphabet of ' +
        kit.esc(String(info.alphabetSize)) + '. That is the number that ' +
        'matters rather than the length, and it is what makes the rate limit ' +
        'on the recovery screen a belt rather than the whole ' +
      'trousers.</td></tr><tr><th>Alphabet</th><td><code>' +
      kit.esc(info.alphabet) + '</code> — the ' +
        'same thirty-two characters RFC 4648 base32 uses, and <strong>not ' +
        'shared with <a href="/admin/totp">TOTP</a></strong>. That one is ' +
        'base32 because the <code>otpauth</code> URI says so; this one is ' +
        'these characters because <strong>no pair of them is ' +
        'confusable</strong> — no <code>0</code> beside <code>O</code>, no ' +
        '<code>1</code> beside <code>I</code> — and a recovery code is the ' +
        'one credential here that somebody writes on paper and types back ' +
        'months later.</td></tr><tr><th>Generated</th><td>' +
        kit.esc(info.source) +
      '</td></tr><tr><th>Compared</th><td>' + kit.esc(info.comparison) + ' ' +
        'Every code in the set is compared even after a match, so the time ' +
        'taken does not depend on WHICH one matched.</td></tr><tr><th>At ' +
        'rest</th><td>' + kit.esc(info.atRest) + '</td></tr>' +
      '</table>' +
      '<h3>What this service will not do with them</h3>' +
      kit.note('<strong>There is no control anywhere that issues a set on ' +
      'request.</strong> Not on this console, not on ' +
      '<code>/admin-api</code>, not on <code>/portal</code>. A set is ' +
      'created by the ACT of enrolling a second factor and by nothing else, ' +
      'because a way back that somebody has to remember to ask for produces ' +
      'exactly the population it exists to protect — the people who did not ' +
      'ask are the people who will need it.') +
      kit.note('<strong>A set is issued ONCE and is never topped ' +
      'up.</strong> Enrolling a different second factor does not reissue: ' +
      'somebody who printed a list in March and replaced their authenticator ' +
      'app in June would otherwise be holding a page of strings that had ' +
      'stopped working with nothing having said so. The only route to a ' +
      'second set is an operator\'s Clear on that person\'s row under <a ' +
      'href="/admin/users">Users</a>, after which the next enrolment issues ' +
      'one.') +
      kit.note('<strong>This console never shows a code.</strong> The ' +
      'person reads their own set back on <code>/portal/mfa</code> and ' +
      'nowhere else. Showing them here would hand a working second factor to ' +
      'whoever holds Admin Read, which is the same door this console already ' +
      'refuses to open for an authenticator enrolment.') +
      kit.note('<strong>A recovery code is never a FIRST factor and never ' +
      'the factor a sign-in asks for.</strong> ' +
      '<code>credentials.mechanismsFor().secondFactor</code> answers ' +
      '<code>webauthn</code> or <code>totp</code> and never this; the ' +
      'recovery screen is reachable only as a way OUT of one of those two, ' +
      'with a step id the person already holds.');
    return html;
  }

  // The /admin/webauthn status block (#446): what the console drew from its
  // JSON.
  /**
   * Draws the status block of /admin/webauthn from its JSON.
   *
   * @param info - the block's JSON, the page view's `status`
   * @returns the block as HTML
   */
  static webauthnStatus(info: Json): string {
    const algorithmRows = info.algorithms.map(function (alg) {
      return '<tr><td><code>' + kit.esc(alg.name) + '</code></td>' +
        '<td class="num"><code>' + kit.esc(String(alg.coseAlg)) +
        '</code></td><td>' + (alg.offered
          ? '<span class="state-valid">offered</span>'
          : '<span class="state-none">verifiable, not offered</span>') +
        '</td></tr>';
    }).join('');
    const html = '<h2>The ceremony</h2>' +
      (info.offered
        ? ''
        : kit.warn('<strong><code>webauthn.enabled</code> is off</strong>, ' +
          'so no new security key can be enrolled here. <strong>It does not ' +
          'disable a key somebody already holds</strong>, for ' +
          'the TOTP row\'s reason — and there is a sharper ' +
          'edge: somebody whose only credential is a <code>primary</code> ' +
          'key would be locked out of their own account by this switch. ' +
          'Removing a key is on that person\'s row under <a ' +
          'href="/admin/users">Users</a>.')) +
      '<table class="key"><tr><th>What</th><th>Answer</th></tr>' +
      '<tr><th>RP ID</th><td>' +
        (info.rpId
          ? '<code>' + kit.esc(info.rpId) + '</code> — configured. It is ' +
            'used only where it is a <strong>registrable domain ' +
            'suffix</strong> of the host this service was reached on; ' +
            'anything else is refused here, with the reason in the log, ' +
            'because a browser would refuse it with an error ' +
            'indistinguishable from a hardware failure.'
          : 'the host this service was reached on. That is the default and ' +
            'it is what a credential is bound to.') + '</td></tr>' +
      '<tr><th>RP name</th><td><code>' + kit.esc(info.rpName) + '</code> — ' +
        'what a browser shows while somebody decides. It has no security ' +
        'meaning: WebAuthn binds a credential to the RP ID and to nothing ' +
        'else.</td></tr><tr><th>User ' +
        'verification</th><td><code>' + kit.esc(info.userVerification) +
        '</code> — ' + (info.userVerificationEnforced
          ? '<strong>requested AND CHECKED</strong>. The UV flag is inside ' +
            'the bytes the authenticator signed, so an authenticator that ' +
            'did not verify the person is refused rather than quietly ' +
            'accepted. It is the only ceremony option on this page this ' +
            'service can check, because it is the only one anything signed ' +
            'says anything about.'
          : 'requested only. Nothing is refused on it.') + '</td></tr>' +
      '<tr><th>Attestation</th><td><code>' + kit.esc(info.attestation) +
      '</code>, conveyance requested' +
        (info.attestationDemandsTrust && info.attestation !== 'enterprise' &&
         info.attestation !== 'direct'
          ? ' — and <strong>sent as <code>direct</code></strong>, because ' +
            'this realm requires a trusted statement and a browser asked ' +
            'for less may strip it'
          : '') +
        '. What is done with the statement is the next section.</td></tr>' +
      '<tr><th>Timeout</th><td>' + kit.esc(String(info.timeoutMs)) + 'ms, ' +
        'and it is a HINT: the specification lets a client clamp it and ' +
        'browsers do. The pending step this service holds expires on its own ' +
        'five-minute clock regardless.</td></tr><tr><th>Signature ' +
        'counter</th><td>' + kit.esc(info.signatureCounter) +
        '</td></tr>' +
      '</table>' +
      ProtocolSettingsPage.attestationPolicyBlock(info) +
      '<h3>CTAP</h3>' +
      kit.note('These three are what a browser translates into what it asks ' +
      'the AUTHENTICATOR for. <strong>They are requests and not ' +
      'checks</strong>: nothing signed says what the browser was asked for, ' +
      'so a check here would be a comparison against a value this service ' +
      'itself supplied. What this service does instead is RECORD what came ' +
      'back, beside the key.') +
      '<table class="key"><tr><th>What</th><th>Answer</th></tr>' +
      '<tr><th>Attachment</th><td>' +
        (info.authenticatorAttachment === 'any'
          ? 'no preference sent, so any authenticator may answer — the ' +
            'member is omitted from the options rather than sent as a wide ' +
            'value, because the dictionary has no value meaning ' +
            '&ldquo;any&rdquo;'
          : '<code>' + kit.esc(info.authenticatorAttachment) + '</code> ' +
            'only. The browser filters; this service does not refuse a ' +
            'credential whose attachment turned out to be the other one.') +
            '</td></tr>' +
      '<tr><th>Discoverable credential</th><td><code>' +
      kit.esc(info.residentKey) +
        '</code> — a CTAP2 <em>resident key</em>, stored on the ' +
        'authenticator itself. That is what a passkey is and what a ' +
        'usernameless sign-in needs. <strong>This service offers no ' +
        'usernameless flow</strong>, so <code>required</code> consumes one ' +
        'of the small number of slots a roaming authenticator has — which ' +
        'cannot always be freed again — and buys nothing here beyond seeing ' +
        'what a client does when the browser prompts differently.</td></tr>' +
      '<tr><th>credProps</th><td>' + (info.credProps
        ? 'asked for. It is the only way to find out whether a ' +
          '<code>preferred</code> ceremony actually produced a discoverable ' +
          'credential — nothing in the attestation says. The answer is ' +
          'recorded beside the key and decides nothing.'
        : 'not asked for, so nothing here knows whether an enrolled ' +
          'credential is discoverable.') + '</td></tr></table><h3>What a key ' +
      'may BE here</h3>' +
      kit.note('The three rows below are <strong>not WebAuthn</strong>. ' +
      'They are what THIS service will do with a key once the ceremony is ' +
      'over, decided here rather than by any specification — and all three ' +
      'refuse an <strong>enrolment</strong> and never an authentication. A ' +
      'key already on somebody\'s entry goes on working when the role that ' +
      'produced it is switched off.') +
      '<table class="key"><tr><th>What</th><th>Answer</th></tr>' +
      '<tr><th>Primary (passwordless)</th><td>' + (info.primaryAllowed
        ? '<span class="state-valid">allowed</span> — a key may be the only ' +
          'credential on an account. The session then records <code>amr ' +
          '["hwk"]</code> and <code>acr "1"</code>.'
        : '<span class="state-none">not allowed</span> — the passwordless ' +
          'box is off the sign-in screen and the <code>primary</code> choice ' +
          'is off the portal.') + '</td></tr>' +
      '<tr><th>Second factor</th><td>' + (info.mfaAllowed
        ? '<span class="state-valid">allowed</span> — beside a password. The ' +
          'session then records <code>amr ["pwd","hwk"]</code> and <code>acr ' +
          '"mfa"</code>.'
        : '<span class="state-none">not allowed</span> — the other second ' +
          'factor is <a href="/admin/totp">an authenticator ' +
          'app</a>.') + '</td></tr>' +
      '<tr><th>Keys per person</th><td>' +
      kit.esc(String(info.maxKeysPerPerson)) +
        '. Several is the ordinary case and the specification expects it: an ' +
        'assertion NAMES the credential that produced it, so there is none ' +
        'of the ambiguity two shared secrets would have.</td></tr>' +
      '</table>' +
      '<h3>Algorithms</h3>' +
      kit.note('<code>pubKeyCredParams</code> is built from the OFFERED ' +
      'rows, in order. The list is filtered against what ' +
      '<code>authn/webauthn.js</code> can actually verify — a name outside ' +
      'that table is dropped with a warning rather than sent, because ' +
      'offering an algorithm this service cannot check produces a credential ' +
      'that enrols perfectly and then fails every assertion it is ever used ' +
      'for, at sign-in rather than at enrolment.') +
      '<table><tr><th>Algorithm</th><th ' +
      'class="num">COSE</th><th>State</th></tr>' +
      algorithmRows + '</table>' +
      '<p class="sub">Curves: ' +
      info.curves.map(function (curve) {
        return '<code>' + kit.esc(curve.name) + '</code>';
      }).join(', ') + '.</p>';
    return html;
  }

  static attestationPolicyBlock(info) {
    const mds = info.mds;
    const policyText = {
      off: 'nothing is verified — the format is recorded and the ' +
           'statement believed. Development only.',
      'verify-if-present': 'every statement that arrives is VERIFIED by ' +
           'its format\'s procedure and refused if it does not verify; a ' +
           'chain is checked against the anchors below, and a model the ' +
           'FIDO Metadata Service lists must chain to the roots it lists ' +
           'and is refused when MDS reports it compromised. ' +
           '<code>none</code> and self attestation are accepted as ' +
           'untrusted — which is what a synced passkey sends.',
      'require-trusted': 'only a statement that CHAINS TO AN ANCHOR is ' +
           'accepted: no <code>none</code>, no self attestation, and so no ' +
           'synced passkey.'
    };
    const html = '<h3>The attestation statement</h3>' +
      '<table class="key"><tr><th>What</th><th>Answer</th></tr>' +
      '<tr><th>Policy</th><td><code>' + kit.esc(info.attestationPolicy) +
        '</code>' + (info.attestationPolicyConfigured === 'by-mode'
          ? ' (<code>by-mode</code>)' : '') + ' — ' +
        (policyText[info.attestationPolicy] || '') +
        (info.attestationDemandsTrust &&
         info.attestationPolicy !== 'require-trusted'
          ? ' <strong>A trusted statement is required anyway</strong>, by ' +
            'the allow-list, certification level or FIPS rows below.'
          : '') + '</td></tr>' +
      '<tr><th>Formats verified</th><td>' +
        info.attestationFormats.map((f) => {
          return '<code>' + kit.esc(f) + '</code>';
        }).join(', ') + ' — all eight of WebAuthn Level 3 section 8.' +
        '</td></tr>' +
      '<tr><th>Trust anchors</th><td>' +
        kit.esc(String(info.attestationTrustAnchors)) + ' configured ' +
        '(<code>webauthn.attestationTrustAnchors</code>), and the roots ' +
        'the FIDO Metadata Service lists for each model.</td></tr>' +
      '<tr><th>FIDO Metadata Service</th><td>' +
        (!mds || !mds.known
          ? 'not read in this process yet — the next draw has it.'
          : (mds.active
              ? 'BLOB <code>' + kit.esc(String(mds.serial)) + '</code> (' +
                kit.esc(String(mds.rows)) + ' key(s)), next due ' +
                kit.esc(mds.nextUpdateAt
                  ? new Date(mds.nextUpdateAt).toISOString().slice(0, 10)
                  : 'unstated') +
                (mds.stale ? ' — <strong>STALE</strong>, so no model is ' +
                             'known from it' : '')
              : 'no BLOB is active, so no model\'s roots or status are ' +
                'known.') +
            ' ' + (mds.url
              ? 'Downloaded from <code>' + kit.esc(mds.url) + '</code> by ' +
                'the <code>' + kit.esc(mds.job) + '</code> job.'
              : 'Uploaded on <a href="/admin/risk">Monitoring → Risk</a> ' +
                '(<code>risk.mdsUrl</code> is empty).')) +
        '</td></tr>' +
      '<tr><th>Allowed models</th><td>' +
        (info.attestationAllowedAaguids.length
          ? info.attestationAllowedAaguids.map((a) => {
            return '<code>' + kit.esc(a) + '</code>';
          }).join(', ')
          : 'any the policy accepts') + '</td></tr>' +
      '<tr><th>Certification</th><td>at least <code>' +
        kit.esc(info.attestationMinCertificationLevel) + '</code>' +
        (info.attestationRequireFips ? ', and FIPS 140 certified' : '') +
        '</td></tr>' +
      '<tr><th>android-safetynet</th><td>' +
        (info.attestationAllowSafetynet
          ? '<strong>trusted</strong> — deprecated, and Google no longer ' +
            'runs the service'
          : 'verified and recorded as untrusted (deprecated)') + '</td></tr>' +
      '<tr><th>android-key</th><td>' +
        (info.attestationAndroidSoftwareKeys
          ? 'the software- and hardware-enforced lists'
          : 'the hardware-enforced (TEE) list only') + '</td></tr>' +
      '</table>' +
      kit.note('What a key\'s statement proved is on its row under <a ' +
      'href="/admin/users">Users</a> and on <code>/portal/keys</code>: ' +
      'the format, whether it was verified and trusted, and the model the ' +
      'metadata names.');
    return html;
  }
}

export = ProtocolSettingsPage;
