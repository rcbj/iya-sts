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
    const settings = json.settings;
    const snapshot = { tokens: json.tokens, overridable: json.overridable,
                       context: json.context };
    const anyOverridden =
        settings.some(function (setting) { return setting.overridden; });

    const inner = kit.note('How long an access token, an ID Token and a ' +
      'refresh token ' +
      'issued here are good for, how long a refresh chain may sit unused, ' +
      'whether a sign-out revokes the refresh tokens of its session, and ' +
      'how far out a clock may be before this service stops believing one ' +
      'of its own. All six are <a ' +
      'href="/admin/oauth2">configuration settings</a> and this page is a ' +
      'shorter way to the same six rows — it writes through the same ' +
      'function, so a change made here and one made there are one change.') +

      kit.warn('<strong>A change applies to the NEXT token and to nothing ' +
      'already issued.</strong> A lifetime is stamped into a token as its ' +
      '<code>exp</code> claim when it is signed, so a token in a client’s ' +
      'hands cannot be shortened or extended afterwards by anything on ' +
      'this page. That is a property of a signed statement rather than a ' +
      'limitation here — to take an issued token out of circulation, ' +
      'revoke it on <a href="/admin/tokens">the tokens page</a>. ' +
      SettingsForms.durability(json.context)) +

      TokenLifetimesPage.tokenLifetimeWarningsFor(
        json.lifetimes.accessTokenTtlS, json.lifetimes.refreshTokenTtlS,
        json.lifetimes.clockSkewS) +

      '<h2>The six settings</h2>' +
      kit.note('Every lifetime is a whole number of ' +
      '<strong>thirty-second</strong> units. That is not a formatting ' +
      'rule: these exist to be set short and watched, and below half a ' +
      'minute a token expires between the response being written and the ' +
      'client reading it, which is an hour spent debugging the wrong half. ' +
      'The clock skew is capped at <strong>300 seconds</strong> — five ' +
      'minutes is the allowance Kerberos uses here ' +
      '(<code>krb5.clockSkew</code>), and a window wider than that has ' +
      'stopped being a tolerance and become a lifetime extension nobody ' +
      'asked for.') +
      '<form method="post" action="/admin/token-lifetimes"><input ' +
      'type="hidden" name="action" ' +
      'value="set"><table><tr><th>Setting</th><th>Value</th><th>Which ' +
      'is</th><th>Per client</th><th>Source</th><th>Tokens of that kind ' +
      'held here</th></tr>' +
      settings.map(function (setting) {
        return TokenLifetimesPage.tokenLifetimeRow(setting, snapshot);
      })
              .join('') +
      '</table>' +
      // The caption is a fold BELOW the button rather than a span beside it,
      // and the reason is markup rather than taste: a <details> inside a <p>
      // is invalid and every browser closes the paragraph in front of it,
      // which leaves the fold outside the form it belongs to.
      '<p><button>Save lifetimes</button></p>' +
      kit.note('All six are checked before any is applied — a form that ' +
      'took two and refused the third would leave this service issuing a ' +
      'combination nobody chose.') +
      '</form>' +

      (anyOverridden
        ? '<div class="ok">' +
          kit.esc(String(settings.filter(function (s) {
            return s.overridden;
          }).length)) +
          ' of the six are set here, ' +
          SettingsForms.overrideKept(json.context) + '. <form method="post" ' +
          'action="/admin/token-lifetimes" class="inline"><input ' +
          'type="hidden" name="action" value="defaults"><button ' +
          'class="secondary">Put these six back</button></form> It clears ' +
          'the override on these six only, and leaves any other setting ' +
          'alone — <a href="/admin/config">Configuration</a> has the ' +
          'reset-all.</div>'
        : kit.note('None of the six is overridden: each is coming from ' +
          'its environment variable, from ' +
          '<code>' + kit.esc((json.context || {}).configFile || 'the ' +
              'appconfig file') +
          '</code>, or from <code>' +
            kit.esc((json.context || {}).defaultsFile) +
          '</code> under it. The <em>Source</em> column says which.')) +

      '<h2>The clock skew is not a lifetime, and it is not the assertion ' +
      'skew either</h2>' +
      kit.note('<code>oauth2.clockSkewS</code> is the allowance applied ' +
      'to <code>exp</code> and <code>nbf</code> at every place this ' +
      'service reads back a token it signed: ' +
      '<code>/oauth2/introspect</code>, UserInfo, the refresh grant, token ' +
      'exchange, the DPoP-bound access token check the four protected ' +
      'endpoints share, and the state column on every console screen that ' +
      'reports one. It never changes what goes INTO a token. It is ' +
      'deliberately a different setting from ' +
      '<code>oauth2.clientAssertionSkewS</code>, which is how far out a ' +
      '<em>client’s</em> assertion may be under RFC 7523 ' +
      '(<code>private_key_jwt</code> and <code>client_secret_jwt</code>): ' +
      'one is about somebody else’s clock and one is about this service’s, ' +
      'and a deployment wanting a strict check on one and a forgiving ' +
      'reading of the other has to be able to say so.') +

      '<h2>What is already out there</h2>' +
      kit.note('Counted against the same clock the endpoints use — the ' +
      'skew above is applied here too, so a token this table calls expired ' +
      'is one <code>/oauth2/introspect</code> will report inactive. ' +
      kit.esc(String(json.tokens.held)) + ' token(s) are held, of the ' +
        'most recent ' +
      kit.esc(String(json.tokens.cap)) + '; ' +
      kit.esc(String(json.tokens.forgotten)) +
      ' older one(s) have been forgotten. Every one of them, with its own ' +
      'expiry, is on <a href="/admin/tokens">the tokens page</a>.') +
      '<table><tr><th>Kind</th><th class="num">Issued</th><th ' +
      'class="num">Valid</th><th class="num">Expired</th><th ' +
      'class="num">Revoked</th><th class="num">Not yet valid</th><th ' +
      'class="num">No expiry stated</th></tr>' +
      (json.tokens.byKind.map(function (row) {
        return '<tr><td><code>' + kit.esc(row.kind) + '</code></td>' +
          '<td class="num">' + row.issued + '</td>' +
          '<td class="num state-valid">' + row.valid + '</td>' +
          '<td class="num state-expired">' + row.expired + '</td>' +
          '<td class="num state-revoked">' + row.revoked + '</td>' +
          '<td class="num state-expired">' + row.notYetValid + '</td>' +
          '<td class="num state-none">' + row.noExpiry + '</td></tr>';
      }).join('') ||
       '<tr><td colspan="7">Nothing has been issued yet.</td></tr>') +
      '</table>' +

      '<h2>The refresh idle timeout is not the refresh lifetime</h2>' +
      kit.note('RFC 9700 mode’s <strong>refresh idle timeout</strong> ' +
      '(<code>oauth2.refreshIdleSeconds</code>, in the table above) is a ' +
      'different question from the refresh lifetime beside it: it is ' +
      'measured ' +
      'from the last time any token in a refresh CHAIN was redeemed rather ' +
      'than from issuance, so a busy client keeps its grant indefinitely ' +
      'and a quiet one is cut off. The lifetime here is a wall the chain ' +
      'cannot be refreshed past however busy it is. An ' +
      '<strong>authorization code</strong>’s lifetime is not set here: ' +
      'it is <code>oauth2.authorizationCodeTtlS</code>, on <a ' +
      'href="/admin/oauth2">the OAuth 2.0 / OIDC settings</a>.') +

      kit.note('The same six over JSON are at ' +
      '<code>/admin/token-lifetimes?format=json</code> and <code>GET ' +
      '/admin-api/token-lifetimes</code>; the two actions on this page are ' +
      '<code>POST /admin-api/token-lifetimes/set</code> and ' +
      '<code>/defaults</code>. They are also six ordinary rows of ' +
      '<code>GET /admin-api/config</code>.');

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
   * @returns the table row as HTML
   */
  static tokenLifetimeRow(setting, snapshot) {
    const id = 'tl-' + setting.key.replace(/\./g, '-');
    const kind = TOKEN_LIFETIME_KINDS[setting.key];
    const counts = kind
      ? (snapshot.tokens.byKind.filter(function (row) {
        return row.kind === kind;
      })[0] || null)
      : null;
    const issued = counts
      ? '<span class="state-valid">' + counts.valid + ' valid</span>, ' +
        '<span class="state-expired">' + counts.expired + ' expired</span>, ' +
        '<span class="state-revoked">' + counts.revoked + ' revoked</span>'
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
      : '<span class="state-none">not per client</span>';
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
          snapshot.context || {})) + '</strong>'
        : kit.esc(SettingsForms.sourceNote(setting, snapshot.context || {}))) +
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
   * @returns the warnings as HTML, or '' for none
   */
  static tokenLifetimeWarningsFor(access, refresh, skew) {
    const notes = [];
    if (access >= refresh) {
      notes.push('<strong>The access token lives at least as long as the ' +
                 'refresh token</strong> (' +
        kit.esc(kit.humanSeconds(access)) + ' against ' +
        kit.esc(kit.humanSeconds(refresh)) +
                 '). ' +
        'That is legal and it is issued exactly as configured, but the grant ' +
        'can never usefully be renewed: by the time a client needs a new ' +
        'access token, the credential it would renew with has expired too. ' +
        'It is a good way to watch a client discover that it has no way back.');
    }
    if (skew >= access) {
      notes.push('<strong>The clock skew is at least as long as the access ' +
        'token’s own lifetime</strong> ' +
        '(' + kit.esc(kit.humanSeconds(skew)) + ' against ' +
        kit.esc(kit.humanSeconds(access)) +
        '). Every endpoint that reads one back will accept it for its whole ' +
        'life and then for as long again, so an expired access token is ' +
        'never refused anywhere here — including at introspection, which ' +
        'will keep reporting it active. Lower the skew, or raise the ' +
        'lifetime, unless that is the thing being tested.');
    }
    if (!notes.length) {
      return '';
    }
    return notes.map(function (note) { return kit.warn(note); }).join('');
  }
}

export = TokenLifetimesPage;
