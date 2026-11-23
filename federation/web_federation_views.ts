// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_federation_views.ts
//
// ---------------------------------------------------------------------------
// THE FEDERATION PAGES' RENDERERS (#580, 2026-10-12).
//
// Each page is drawn from the view its shell carried (`federation_pages.ts`,
// `data-sts-state`), by the view's `kind`:
//
//   * `index` — the landing page `GET /federation`, every word from the
//     `federationPages` catalogs;
//   * `signedIn` — the linking step's outcome, where nothing asked to be
//     returned to: the page `federation_sp.ts`'s `signedInPage()` still
//     draws for the assertion consumer service, in the same `handoff`
//     catalogs' words;
//   * `profile` — what a consumer provider's newcomer is asked for before
//     the account is created (#729), its words from `federationPages`;
//   * `refused`, `off`, `noRelationship` — what the login and linking
//     endpoints say when they will not go on: in the page's language since
//     #2006 (English, every word, until then: #539's
//     decision 6), as the server drew them, through the one outcome
//     renderer (`common/web_outcome.ts`).
//
// What a partner sent, the mapping's own words and setting names are DATA
// and are drawn as they are, escaped.
//
// A `web_` MODULE: it requires other `web_` modules only and logs nothing.
// ---------------------------------------------------------------------------

import WebOutcome = require('../common/web_outcome');
import WebSaid = require('../common/web_said');

type Json = any;

const esc = WebOutcome.esc;

// Where the pages link to, root-relative: the realm's prefix is put on by
// the runtime (`WebPage.realmLinks()`).
const INDEX_PATH = '/federation';
const CONSOLE_PATH = '/admin/federation';

/**
 * The federation pages' renderers. A static utility class.
 */
class WebFederationViews {
  /**
   * Draws a view by its kind.
   *
   * @param view - the view
   * @param ctx - the context (`t`)
   * @returns the body
   */
  static render(view: Json, ctx: Json): string {
    const v = view || {};
    if (v.kind === 'index') {
      return WebFederationViews.index(v, ctx.t);
    }
    if (v.kind === 'signedIn') {
      return WebFederationViews.signedIn(v, ctx.t);
    }
    if (v.kind === 'profile') {
      return WebFederationViews.profile(v, ctx.t);
    }
    if (v.kind === 'refused') {
      return WebFederationViews.refused(v, ctx.t);
    }
    if (v.kind === 'webfinger') {
      return WebFederationViews.webfinger(v, ctx.t);
    }
    if (v.kind === 'off') {
      return WebFederationViews.off(ctx.t);
    }
    if (v.kind === 'noRelationship') {
      return WebFederationViews.noRelationship(v, ctx.t);
    }
    return WebOutcome.draw({
      heading: WebFederationViews.refusal('refusals.web.notDrawnTitle', {},
                                          'This page could not be drawn',
                                          ctx.t),
      why: WebFederationViews.refusal('refusals.federation.unknownView',
        { kind: String(v.kind) }, 'The service sent a view this page does ' +
        'not know (' + String(v.kind) + ').', ctx.t), whyTone: 'err' });
  }

  /**
   * The document's title for a view, as text.
   *
   * @param view - the view
   * @param ctx - the context (`t`)
   * @returns the title
   */
  static title(view: Json, ctx: Json): string {
    const kind = String((view && view.kind) || '');
    if (kind === 'index') {
      return ctx.t.text('federationPages.index.title');
    }
    if (kind === 'signedIn') {
      return ctx.t.text('handoff.federation.signedIn.title');
    }
    if (kind === 'profile') {
      return ctx.t.text('federationPages.profile.title');
    }
    if (kind === 'refused') {
      return WebFederationViews.refusal('refusals.federation.title.refused',
                                        {}, 'Refused', ctx.t);
    }
    if (kind === 'webfinger') {
      return ctx.t.text('federationPages.webfinger.title');
    }
    if (kind === 'noRelationship') {
      return WebFederationViews.refusal(
        'refusals.federation.title.noRelationship', {},
        'No such relationship', ctx.t);
    }
    return kind === 'off'
      ? WebFederationViews.refusal('refusals.federation.title.notHere', {},
                                   'Not here', ctx.t)
      : 'Federation';
  }

  /**
   * The landing page: what federation is here, the relationships in each
   * direction, and the endpoints.
   *
   * @param v - the `index` view
   * @param t - the translator
   * @returns the body
   */
  static index(v: Json, t: Json): string {
    const paths = v.paths || {};
    const consuming = (Array.isArray(v.consuming) ? v.consuming : [])
      .map(function (one: Json): string {
        const state = one.state === 'ready'
          ? t.html('federationPages.index.ready')
          : (one.state === 'incomplete'
              ? t.html('federationPages.index.incomplete',
                       { missing: (one.missing || []).join(', ') })
              : t.html('federationPages.index.disabled'));
        return '<tr><td><code>' + esc(one.id) + '</code></td><td>' +
          esc(one.protocol) + '</td><td><code>' +
          (one.peer ? esc(one.peer)
                    : t.html('federationPages.index.noneSet')) +
          '</code></td><td class="' + (one.state === 'ready' ? 'ok' : 'bad') +
          '">' + state + '</td><td>' +
          (one.state === 'ready'
            ? '<a href="' + esc(paths.login + '/' +
                                encodeURIComponent(one.id)) + '">' +
              t.html('federationPages.index.signIn') + '</a>'
            : '<span class="meta">—</span>') +
          (one.metadata
            ? ' · <a href="' + esc(paths.metadata + '/' +
                                   encodeURIComponent(one.id)) + '">' +
              t.html('federationPages.index.metadata') + '</a>'
            : '') + '</td></tr>';
      }).join('');
    const asserting = (Array.isArray(v.asserting) ? v.asserting : [])
      .map(function (one: Json): string {
        return '<tr><td><code>' + esc(one.id) + '</code></td><td>' +
          esc(one.protocol) + '</td><td><code>' +
          (one.application ? esc(one.application)
                           : t.html('federationPages.index.noApplication')) +
          '</code></td><td>' +
          ((one.release || []).length
            ? esc(one.release.join(', '))
            : '<span class="meta">' +
              t.html('federationPages.index.noRelease') + '</span>') +
          '</td></tr>';
      }).join('');
    const endpoint = function (path: string, what: string): string {
      return '<tr><td><code>' + esc(path) + '/{id}</code></td><td>' + what +
        '</td></tr>';
    };
    return '<h1>' + t.html('federationPages.index.title') + '</h1>' +
      '<p>' + t.html('federationPages.index.lead') + '</p>' +
      '<p class="meta">' + t.html('federationPages.index.note') + '</p>' +
      '<h2>' + t.html('federationPages.index.consuming') + '</h2>' +
      (consuming
        ? '<table id="federation-consuming"><tr><th>' +
          t.html('federationPages.index.relationship') + '</th><th>' +
          t.html('federationPages.index.protocol') + '</th><th>' +
          t.html('federationPages.index.partner') + '</th><th>' +
          t.html('federationPages.index.state') + '</th><th></th></tr>' +
          consuming + '</table>'
        : '<p class="meta">' + t.html('federationPages.index.noConsuming') +
          ' <a href="' + CONSOLE_PATH + '">' + CONSOLE_PATH + '</a></p>') +
      '<h2>' + t.html('federationPages.index.asserting') + '</h2>' +
      (asserting
        ? '<table id="federation-asserting"><tr><th>' +
          t.html('federationPages.index.relationship') + '</th><th>' +
          t.html('federationPages.index.protocol') + '</th><th>' +
          t.html('federationPages.index.application') + '</th><th>' +
          t.html('federationPages.index.released') + '</th></tr>' +
          asserting + '</table>'
        : '<p class="meta">' + t.html('federationPages.index.noAsserting') +
          '</p>') +
      '<h2>' + t.html('federationPages.index.endpoints') + '</h2>' +
      '<table><tr><th>' + t.html('federationPages.index.path') +
      '</th><th>' + t.html('federationPages.index.what') + '</th></tr>' +
      // The login path takes `?returnTo=`, said in its own sentence.
      endpoint(String(paths.login),
               t.html('federationPages.index.loginPath')) +
      endpoint(String(paths.acs),
               t.html('federationPages.index.acsPath')) +
      endpoint(String(paths.metadata),
               t.html('federationPages.index.metadataPath')) +
      // A PARTNER'S SIGN-OUT (#167), served by federation_slo.ts.
      endpoint(String(paths.slo),
               t.html('federationPages.index.sloPath')) +
      endpoint(String(paths.backchannel),
               t.html('federationPages.index.backchannelPath')) +
      endpoint(String(paths.frontchannel),
               t.html('federationPages.index.frontchannelPath')) +
      '</table><p class="meta">' +
      t.html('federationPages.index.base', { base: String(v.base || '') }) +
      '</p>' +
      // **`/portal` AND NOT `/authn/login`, WHICH IS NOT A PAGE ANYBODY CAN
      // BE SENT TO.** That page is drawn for a PENDING AUTHENTICATION
      // RECORD and refuses a request naming none, so a link to it was an
      // error page for as long as it existed. `/portal` has no session
      // either, so it sends the browser to begin an authentication and the
      // browser arrives at the very screen this link promises — with the
      // partner buttons on it — and lands on the reader's own account page
      // once they have used one. The record is minted when the link is
      // PRESSED rather than when this page is drawn, which is what keeps it
      // from expiring on a page somebody left open (`portal/CLAUDE.md`).
      '<p><a href="' + CONSOLE_PATH + '">' +
      t.html('federationPages.index.configure') + '</a> · <a href="' +
      '/portal">' + t.html('federationPages.index.signInScreen') +
      '</a></p><p class="meta" id="federation-buttons">' +
      t.html(v.loginButtons ? 'federationPages.index.buttonsOn'
                            : 'federationPages.index.buttonsOff') + '</p>';
  }

  /**
   * The linking step's outcome: who the person is signed in as, what the
   * partner sent and what became of it — `signedInPage()`'s page.
   *
   * @param v - the `signedIn` view
   * @param t - the translator
   * @returns the body
   */
  static signedIn(v: Json, t: Json): string {
    const lines = function (values: Json): string {
      return (values || []).map(function (one: Json): string {
        return esc(one);
      }).join('<br>');
    };
    const unmappedRows = (v.unmapped || []).map(function (one: Json): string {
      return '<tr><td><code>' + esc(one.incoming) + '</code></td><td ' +
        'colspan="2">' + lines(one.values) + '</td><td class="meta">' +
        t.html('handoff.federation.signedIn.notWritten') + '</td></tr>';
    }).join('');
    const mappedRows = (v.mapped || []).map(function (one: Json): string {
      return '<tr><td><code>' + esc(one.incoming) + '</code></td><td><code>' +
        esc(one.ldap) + '</code></td><td>' + lines(one.values) +
        '</td><td class="meta">' + esc(one.where) + '</td></tr>';
    }).join('');
    const inConsole = CONSOLE_PATH + '?relationship=' +
      encodeURIComponent(String(v.relationship || ''));
    return '<h1 id="federation-signed-in">' +
      t.html('handoff.federation.signedIn.heading',
             { partner: String(v.partner || '') }) + '</h1><p>' +
      t.html('handoff.federation.signedIn.lead',
             { username: String(v.username || ''),
               session: String(v.session || '') }) +
      '</p><table><tr><th>' + t.html('handoff.federation.signedIn.what') +
      '</th><th>' + t.html('handoff.federation.signedIn.value') +
      '</th></tr><tr><td>' + t.html('handoff.federation.signedIn.partner') +
      '</td><td><code>' + (v.peer ? esc(v.peer)
        : t.html('handoff.federation.signedIn.unnamed')) +
      '</code></td></tr><tr><td>' +
      t.html('handoff.federation.signedIn.protocol') + '</td><td>' +
      esc(v.protocol) + '</td></tr><tr><td>' +
      t.html('handoff.federation.signedIn.subject') + '</td><td><code>' +
      (v.subject ? esc(v.subject)
                 : t.html('handoff.federation.signedIn.none')) +
      '</code></td></tr><tr><td>' +
      t.html('handoff.federation.signedIn.usernameHere') +
      '</td><td><code>' + esc(v.username) + '</code>' +
      (v.usernamePrefixed
        ? ' <span class="meta">' +
          t.html('handoff.federation.signedIn.prefixed') + '</span>'
        : '') + ' <span class="meta">' +
      t.html('handoff.federation.signedIn.from',
             { source: String(v.usernameFrom || '') }) +
      '</span></td></tr><tr><td>' +
      t.html('handoff.federation.signedIn.entry') + '</td><td>' +
      (v.autocreate
        ? t.html('handoff.federation.signedIn.created') + ' ' +
          '<a href="/admin/users">/admin/users</a>'
        : '<span class="meta">' +
          t.html('handoff.federation.signedIn.neverCreated') + '</span>') +
      (v.updates
        ? t.html('handoff.federation.signedIn.updated')
        : '<span class="meta">' +
          t.html('handoff.federation.signedIn.writtenOnce') + '</span>') +
      '</td></tr></table>' +
      (mappedRows
        ? '<h2>' + t.html('handoff.federation.signedIn.mappedHeading') +
          '</h2><table><tr><th>' +
          t.html('handoff.federation.signedIn.partnerSent') + '</th><th>' +
          t.html('handoff.federation.signedIn.became') + '</th><th>' +
          t.html('handoff.federation.signedIn.values') + '</th><th>' +
          t.html('handoff.federation.signedIn.decidedBy') + '</th></tr>' +
          mappedRows + unmappedRows + '</table>'
        : '<h2>' + t.html('handoff.federation.signedIn.attributes') +
          '</h2><p class="meta">' +
          t.html('handoff.federation.signedIn.noAttributes') + '</p>' +
          (unmappedRows ? '<table>' + unmappedRows + '</table>' : '')) +
      ((v.unmapped || []).length
        ? '<p class="meta">' +
          t.html('handoff.federation.signedIn.thrownAway',
                 { n: v.unmapped.length }) + ' <a href="' + esc(inConsole) +
          '">' + t.html('handoff.federation.signedIn.theRelationship') +
          '</a> ' + t.html('handoff.federation.signedIn.toKeepOne') + '</p>'
        : '') +
      '<p><a href="' + INDEX_PATH + '">' +
      t.html('handoff.federation.signedIn.backToIndex') + '</a> · <a href="' +
      esc(inConsole) + '">' + t.html('handoff.federation.signedIn.inConsole') +
      '</a></p>';
  }

  /**
   * What a consumer provider's newcomer is asked for (#729): exactly the
   * values this realm requires of every person that the provider did not
   * send, in a form posted to `/federation/profile/{handle}` with the
   * step's token. A field's label and a problem the server found are DATA
   * (the attribute's own label, the server's English).
   *
   * @param v - the `profile` view: `action`, `csrf`, `fields`, `partner`,
   *   `provider`, `problem`
   * @param t - the translator
   * @returns the body
   */
  static profile(v: Json, t: Json): string {
    const fields = (Array.isArray(v.fields) ? v.fields : [])
      .map(function (one: Json, at: number): string {
        const id = 'profile-field-' + at;
        return '<label for="' + id + '">' + esc(one.label || one.name) +
          '</label><input type="' + (one.type === 'email' ? 'email'
                                                           : 'text') +
          '" id="' + id + '" name="' + esc(one.name) + '" required ' +
          'maxlength="' + esc(String(Number(one.max) || 256)) + '"' +
          (one.type === 'email' ? ' autocomplete="email"' : '') + '>';
      }).join('');
    return '<h1 id="federation-profile">' +
      t.html('federationPages.profile.heading') + '</h1><p>' +
      t.html('federationPages.profile.lead',
             { partner: String(v.partner || v.provider || '') }) + '</p>' +
      (v.problem
        ? '<div class="err" id="federation-profile-problem">' +
          esc(v.problem) + '</div>'
        : '') +
      '<form method="post" id="federation-profile-form" action="' +
      esc(v.action) + '"><input type="hidden" name="csrf" value="' +
      esc(v.csrf) + '">' + fields + '<div class="row"><button ' +
      'type="submit" id="federation-profile-submit">' +
      t.html('federationPages.profile.submit') + '</button></div></form>' +
      '<p class="meta">' + t.html('federationPages.profile.note') + '</p>';
  }

  /**
   * A person's OpenID Provider found from an identifier they type (#930):
   * the form asking for it, or the issuer found and a link that continues
   * there — nothing continues on its own.
   *
   * @param v - the `webfinger` view: `step` (`ask` or `found`), `partner`,
   *   `action`, `identifier`, `issuer`, `continueHref`
   * @param t - the translator
   * @returns the body
   */
  static webfinger(v: Json, t: Json): string {
    if (v.step === 'found') {
      return '<h1 id="federation-webfinger">' +
        t.html('federationPages.webfinger.heading') + '</h1><p ' +
        'id="federation-webfinger-found">' +
        t.html('federationPages.webfinger.found',
               { identifier: String(v.identifier || ''),
                 issuer: String(v.issuer || '') }) + '</p>' +
        '<p><a class="btn" id="federation-webfinger-continue" href="' +
        esc(v.continueHref) + '">' +
        t.html('federationPages.webfinger.continue') + '</a></p>' +
        '<p class="meta">' + t.html('federationPages.webfinger.note') +
        '</p>';
    }
    return '<h1 id="federation-webfinger">' +
      t.html('federationPages.webfinger.heading') + '</h1><p>' +
      t.html('federationPages.webfinger.lead',
             { partner: String(v.partner || '') }) + '</p>' +
      '<form method="get" id="federation-webfinger-form" action="' +
      esc(v.action) + '"><label for="federation-webfinger-resource">' +
      t.html('federationPages.webfinger.label') + '</label><input ' +
      'type="text" id="federation-webfinger-resource" name="resource" ' +
      'required maxlength="512" autocomplete="username"><div ' +
      'class="row"><button type="submit" id="federation-webfinger-submit">' +
      t.html('federationPages.webfinger.submit') + '</button></div></form>';
  }

  /**
   * A sentence this page writes itself, as text, in the page's language,
   * and in the English given where the catalogs lack it (#2006). The key
   * comes first, as in `WebSurface.refusal()`, so `tests/i18n_catalogs.js`
   * finds it.
   *
   * @param key - the `refusals` key, a literal
   * @param params - its parameters
   * @param english - the English
   * @param t - the translator
   * @returns the sentence, as text
   */
  static refusal(key: string, params: Json, english: string,
                 t: Json): string {
    return WebSaid.sentence(t, { key: key, params: params || {} }) || english;
  }

  /**
   * The same as HTML: the message's own inline markup kept, its parameters
   * escaped; the English given (already HTML) where the catalogs lack it.
   *
   * @param t - the translator
   * @param key - the `refusals` key, a literal
   * @param params - its parameters
   * @param english - the English, as HTML
   * @returns the HTML
   */
  static refusalHtml(t: Json, key: string, params: Json,
                     english: string): string {
    return t && typeof t.has === 'function' && t.has(key)
      ? t.html(key, params || {}) : english;
  }

  /**
   * A refusal of the login or linking endpoint, in the page's language
   * (#2006): `what` and `why` from their catalog messages where the server
   * sent them (`whatMessage`, `whyMessage`), their English otherwise — a
   * partner's or a library's words are drawn as sent — with where it is
   * recorded.
   *
   * @param v - the `refused` view: `what`, `why`, `relationship`
   * @param t - the translator
   * @returns the body
   */
  static refused(v: Json, t: Json): string {
    const id = String(v.relationship || '');
    const notes = [];
    if (id) {
      // The link carries an href, which a message may not, so the note is
      // two messages with the anchor between them.
      notes.push(WebFederationViews.refusalHtml(t,
        'refusals.federation.recordedOnBefore', {},
        'This is recorded on the relationship as ' +
        '<code>fedLastError</code>. The whole record is at') + ' <a href="' +
        CONSOLE_PATH + '?relationship=' + esc(encodeURIComponent(id)) +
        '">' + CONSOLE_PATH + '</a>' +
        WebFederationViews.refusalHtml(t,
          'refusals.federation.recordedOnAfter', {},
          ', and every refusal is also a row in the audit log.'));
    }
    notes.push(WebFederationViews.refusalHtml(t,
      'refusals.federation.refusesHere', {},
      '<strong>This service refuses rather than accepting here, ' +
      'which is the opposite of what it does everywhere else.</strong> ' +
      'What arrives at a federation endpoint is an unauthenticated request ' +
      'claiming to be a person, and the session it would produce is the ' +
      'one every other protocol in this process reads. See ' +
      'federation/CLAUDE.md.'));
    return WebOutcome.draw({
      heading: WebFederationViews.refusal('refusals.federation.refusedHeading',
        {}, 'The federated sign-in was refused', t),
      what: WebSaid.sentence(t, v.whatMessage) || String(v.what || ''),
      why: WebSaid.sentence(t, v.whyMessage) || String(v.why || ''),
      ids: { what: 'federation-refused', why: 'federation-why' },
      notes: notes,
      links: [{ href: INDEX_PATH,
                label: WebFederationViews.refusal(
                  'refusals.federation.backToIndex', {},
                  'Back to the federation index', t) }] });
  }

  /**
   * Federation is turned off, in the page's language (#2006).
   *
   * @param t - the translator
   * @returns the body
   */
  static off(t: Json): string {
    return WebOutcome.draw({
      heading: WebFederationViews.refusal('refusals.federation.offHeading',
                                          {}, 'Federation is off', t),
      ids: { what: 'federation-off' },
      notes: [WebFederationViews.refusalHtml(t, 'refusals.federation.off', {},
        '<code>federation.enabled</code> is off, so no federation ' +
        'endpoint answers. No relationship was changed.')] });
  }

  /**
   * No relationship by the name asked for, in the page's language (#2006).
   *
   * @param v - the `noRelationship` view: `id`
   * @param t - the translator
   * @returns the body
   */
  static noRelationship(v: Json, t: Json): string {
    return WebOutcome.draw({
      heading: WebFederationViews.refusal(
        'refusals.federation.noRelationshipHeading', {},
        'No such federation relationship', t),
      notes: [WebFederationViews.refusalHtml(t,
        'refusals.federation.noRelationship', { id: String(v.id || '') },
        'There is no relationship called <code>' + esc(v.id) +
        '</code>. The configured ones are on the federation index.')],
      links: [{ href: INDEX_PATH, label: INDEX_PATH,
                id: 'federation-index' }] });
  }
}

export = WebFederationViews;
