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
    const settings = json.settings;
    const snapshot = { assertions: { byKind: json.assertionsIssued.byKind },
                       rows: json.rows, seconds: json.seconds,
                       context: json.context };
    const anyOverridden =
        settings.some(function (setting) { return setting.overridden; });

    const inner = kit.note('How long an assertion issued here is valid for, ' +
      'and how ' +
      'far its window is widened at each end to allow for a relying party ' +
      'whose clock disagrees with this one. All three are <a ' +
      'href="/admin/config">configuration settings</a>: the two lifetimes ' +
      'are also drawn on <a href="/admin/saml2">SAML 2.0</a> and <a ' +
      'href="/admin/saml11">SAML 1.1</a>, one on each, and the skew on ' +
      'both. This page is a shorter way to the same rows and the only ' +
      'place all three are visible at once — it writes through the same ' +
      'function, so a change made here and one made there are one change.') +

      kit.warn('<strong>A change applies to the NEXT assertion and to ' +
      'nothing already issued.</strong> A validity window is stamped into ' +
      'an assertion as <code>Conditions/NotBefore</code> and ' +
      '<code>NotOnOrAfter</code> when it is signed, so an assertion ' +
      'already in a relying party&rsquo;s hands cannot be shortened or ' +
      'extended afterwards by anything on this page. Changes are in memory ' +
      'and are gone on restart; to make one stick, put it in <code>' +
      kit.esc((json.context || {}).configFile || 'env/local.js') +
      '</code>.') +

      SamlAssertionsPage.samlAssertionWarnings(json) +

      '<h2>The sixteen settings</h2>' +
      kit.note('<strong>Ten of these eleven are DEFAULTS, not ' +
      'decisions.</strong> Each is what an application gets when its own ' +
      'entry says nothing, and the <em>Per-application</em> column names ' +
      'the attribute that overrides it — set that on an application under ' +
      '<a href="/admin/applications">Applications</a> and this row stops ' +
      'governing it. The eleventh, the clock skew, has no per-application ' +
      'form: it is a fact about the clocks in the estate this service ' +
      'issues into, decided once. <strong>They moved here from the two ' +
      'identity provider pages on 2026-08-27</strong>, because those pages ' +
      'configure this service as an identity provider and these describe ' +
      'what it does for an application nobody has configured.') +
      kit.note('The two lifetimes are in <strong>minutes</strong> and the ' +
      'skew and the two artifact lifetimes are in ' +
      '<strong>seconds</strong>, which is not a formatting accident: a ' +
      'lifetime is set to a number of minutes to watch an assertion go ' +
      'stale, and a skew is a handful of seconds covering the difference ' +
      'between two machines. The skew is capped at <strong>300 ' +
      'seconds</strong> for the reason <code>oauth2.clockSkewS</code> is — ' +
      'five minutes is what Kerberos allows here ' +
      '(<code>krb5.clockSkew</code>), and wider than that the window has ' +
      'stopped being a tolerance and become a lifetime nobody chose.') +
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
                         'Every profile'));
        return '<h3>' + kit.esc(heading) + '</h3>' +
          '<table><tr><th>Setting</th><th>Value</th><th>Which is</th>' +
          '<th>Per-application</th><th>Source</th>' +
          '<th>Assertions held</th></tr>' +
          mine.map(function (setting) {
            return SamlAssertionsPage.samlAssertionSettingRow(setting,
              snapshot);
          }).join('') +
          '</table>';
      }).join('') +
      '<p><button>Save assertion settings</button></p>' +
      kit.note('All sixteen are checked before any is applied — a form ' +
      'that took eleven and refused the twelfth would leave this service ' +
      'issuing a combination nobody chose.') +
      '</form>' +

      (anyOverridden
        ? '<div class="ok">' +
          kit.esc(String(settings.filter(function (s) {
            return s.overridden;
          }).length)) +
          ' of the sixteen are set here, in memory only. <form ' +
          'method="post" action="/admin/saml-assertions" ' +
          'class="inline"><input type="hidden" name="action" ' +
          'value="defaults"><button class="secondary">Put these sixteen ' +
          'back</button></form> It clears the override on these sixteen ' +
          'only, and leaves any other setting alone — <a ' +
          'href="/admin/config">Configuration</a> has the reset-all.</div>'
        : kit.note('None of the sixteen is overridden: each is coming ' +
          'from its environment variable, from ' +
          '<code>' + kit.esc((json.context || {}).configFile || 'the ' +
              'appconfig file') +
          '</code>, or from <code>' +
            kit.esc((json.context || {}).defaultsFile) +
          '</code> under it. The <em>Source</em> column says which.')) +

      '<h2>What the skew actually does to an assertion</h2>' +
      kit.note('It is added at BOTH ends of the window and to neither ' +
      'instant that states when something happened: <code>NotBefore</code> ' +
      'is backdated by it and <code>NotOnOrAfter</code> is extended by it, ' +
      'while <code>IssueInstant</code> and the authentication instant are ' +
      'left at the real time &mdash; backdating those would be a lie about ' +
      'an event rather than an allowance about a clock. So the window an ' +
      'assertion states is its lifetime <em>plus twice</em> the skew, ' +
      'which is why this page reports <code>saml2WindowS</code> and ' +
      '<code>saml11WindowS</code> beside the settings themselves. At the ' +
      'default 0 the documents are byte-for-byte what this service issued ' +
      'before the setting existed.') +
      '<table><tr><th>Profile</th><th>NotBefore</th><th>NotOnOrAfter</th>' +
      '<th class="num">Stated window</th></tr>' +
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
      '</table><h2>It reaches four protocols, and it is not the skew this ' +
      'service reads with</h2>' +
      kit.note('<strong>Four.</strong> WS-Trust and WS-Federation build ' +
      'their assertions with the same two functions the browser profiles ' +
      'use, so both settings above reach them without either module ' +
      'knowing these exist. A WS-Federation sign-in carries a SAML 1.1 ' +
      'assertion, so it is <code>saml11.assertionLifetimeMin</code> that ' +
      'governs it. What those two wrap the assertion in — WS-Trust&rsquo;s ' +
      '<code>wsu:Lifetime</code> and the equivalent in a WS-Federation ' +
      'response — states the LIFETIME without the skew, which is the ' +
      'conservative reading and is deliberate: the envelope describes what ' +
      'was asked for and the assertion states what it is actually valid ' +
      'for.') +
      kit.note('<strong>And it is not ' +
      '<code>oauth2.clockSkewS</code>.</strong> That one is the allowance ' +
      'applied wherever this service READS something back — including an ' +
      'inbound federation partner&rsquo;s SAML assertion at ' +
      '<code>/federation/acs/{id}</code>, which applies it to exactly the ' +
      'two attributes this page writes. This one is what goes INTO a ' +
      'document this service issues. One is about somebody else&rsquo;s ' +
      'clock and one is about how much of somebody else&rsquo;s clock this ' +
      'service pays for in advance, and a deployment wanting a strict ' +
      'reading and a forgiving issuance has to be able to say so. The ' +
      'reading tolerance is on <a href="/admin/token-lifetimes">Token ' +
      'lifetimes</a>.') +

      '<h2>What is already out there</h2>' +
      kit.note('Counted against this service&rsquo;s own clock with no ' +
      'allowance applied — the skew above is written into an assertion ' +
      'rather than applied when one is read here, so an assertion this ' +
      'calls expired is one whose stated <code>NotOnOrAfter</code> has ' +
      'passed. ' + kit.esc(String(json.assertionsIssued.held)) + ' ' +
      'artifact(s) are held, of the most ' +
      'recent ' + kit.esc(String(json.assertionsIssued.cap)) + '; ' +
      kit.esc(String(json.assertionsIssued.forgotten)) + ' older one(s) ' +
      'have been forgotten. Every one of them is on <a ' +
      'href="/admin/tokens">the tokens page</a>, which draws assertions ' +
      'beside the JWTs and the Kerberos tickets.') +
      '<table><tr><th>Profile</th><th class="num">Issued</th><th ' +
      'class="num">Valid</th><th class="num">Expired</th><th ' +
      'class="num">No expiry stated</th></tr>' +
      (json.assertionsIssued.byKind.map(function (row) {
        return '<tr><td><code>' + kit.esc(row.kind) + '</code></td>' +
          '<td class="num">' + row.issued + '</td>' +
          '<td class="num state-valid">' + row.valid + '</td>' +
          '<td class="num state-expired">' + row.expired + '</td>' +
          '<td class="num state-none">' + row.noExpiry + '</td></tr>';
      }).join('')) +
      '</table>' +

      '<h2>Two things about a window this page does not set</h2>' +
      kit.note('A <strong>SAML artifact</strong> is good for ' +
      '<code>saml2.artifactTtlS</code> and is a different clock entirely — ' +
      'it governs how long an artifact can be RESOLVED for, not how long ' +
      'the assertion it resolves to is valid. And the ' +
      '<strong>session</strong> behind an assertion has its own lifetime: ' +
      'an assertion that has expired does not end the sign-on session that ' +
      'produced it, which is why a relying party refusing a stale ' +
      'assertion can be sent straight back here and get a fresh one with ' +
      'no sign-in screen.') +

      kit.note('The same three over JSON are at ' +
      '<code>/admin/saml-assertions?format=json</code> and <code>GET ' +
      '/admin-api/saml-assertions</code>; the two actions on this page are ' +
      '<code>POST /admin-api/saml-assertions/set</code> and ' +
      '<code>/defaults</code>. They are also three ordinary rows of ' +
      '<code>GET /admin-api/config</code>.');

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
   * @param setting - the described setting
   * @param snapshot - the statistics snapshot the assertion counts come from
   * @returns the table row as HTML
   */
  static samlAssertionSettingRow(setting, snapshot) {
    const id = 'sa-' + setting.key.replace(/\./g, '-');
    const row = snapshot.rows.filter(function (one) {
      return one.key === setting.key;
    })[0];
    const counts = (row && row.kind)
      ? (snapshot.assertions.byKind.filter(function (
          k) { return k.kind === row.kind; })[0] || null)
      : null;
    const issued = counts
      ? '<span class="state-valid">' + counts.valid + ' valid</span>, ' +
        '<span class="state-expired">' + counts.expired + ' expired</span>'
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
            kit.esc(option === '' ? '(empty — the default)' : option) +
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
      : '<span class="state-none">not per application</span>';
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
          snapshot.context || {})) + '</strong>'
        : kit.esc(SettingsForms.sourceNote(setting,
          snapshot.context || {}))) + '</td>' +
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
   * @param json - the page's view (`rows`, `seconds`)
   * @returns the warnings as HTML, or an empty string
   */
  static samlAssertionWarnings(json) {
    const skew = json.seconds['saml.clockSkewS'];
    const notes = [];
    json.rows.filter(function (row) { return row.kind; })
                           .forEach(function (row) {
      const lifetime = json.seconds[row.key];
      if (skew > 0 && skew >= lifetime) {
        notes.push('<strong>The clock skew is at least as long as the ' +
          kit.esc(row.kind) +
          ' assertion&rsquo;s own lifetime</strong> (' + kit.esc(
              kit.humanSeconds(skew)) + ' ' +
              'against ' +
          kit.esc(kit.humanSeconds(lifetime)) + '). The window written ' +
          'into the assertion is the lifetime plus the skew at EACH end, so ' +
          'it is valid for at least three times as long as ' +
          '<code>' + kit.esc(row.key) + '</code> says. If the point was to ' +
          'watch a relying party refuse a stale assertion, it will not: ' +
          'lower the skew, or raise the lifetime.');
      }
    });
    if (skew === 0) {
      notes.push('<strong>The skew is 0, which is what this service has ' +
        'always done</strong> &mdash; <code>NotBefore</code> is stamped at ' +
        'exactly the moment of issue. That is the strict reading, and it is ' +
        'the one that fails against a relying party whose clock is a few ' +
        'seconds behind: the assertion is not yet valid when it arrives, and ' +
        'the refusal reads as a signature or trust-store problem from both ' +
        'ends. If a service provider is refusing assertions that look ' +
        'correct, this is the first setting to raise.');
    }
    if (!notes.length) {
      return '';
    }
    return notes.map(function (note) { return kit.warn(note); }).join('');
  }}

export = SamlAssertionsPage;
