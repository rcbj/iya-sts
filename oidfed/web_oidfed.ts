// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_oidfed.ts
//
// ---------------------------------------------------------------------------
// PROTOCOLS → OPENID FEDERATION, DRAWN FROM ITS VIEW ALONE (#446, 2026-10-05).
//
// Draws OpenID Federation from the answer of `GET /admin-api/oidfed`: this
// realm as a federation entity — its configuration, keys, subordinates, the
// collection, its Trust Anchors and Trust Marks, a resolution, and its
// settings.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// Its methods were `OidfedAdmin`'s in `oidfed/oidfed_admin.ts`, moved with
// their comments; that module still draws the page until the console's
// cutover, by calling `render()` with its view passed through JSON.
// ---------------------------------------------------------------------------

import kit = require('../admin-ui/web_kit');
import SettingsForms = require('../admin-ui/web_settings');

type Json = any;

// The console's escaping, under the name the moved code calls it by.
const esc = kit.esc;

// An attribute value from a translated message (#539): escaped, but with the
// apostrophe left as it is, because every attribute here is double-quoted
// and the English placeholders were written with a bare one — esc() would
// turn it into `&apos;` and change the page.
const attr = function (text: string): string {
  return esc(text).replace(/&apos;/g, '\'');
};

/**
 * Draws OpenID Federation from the answer of `GET /admin-api/oidfed`: this
 * realm as a federation entity — its configuration, keys, subordinates, the
 * collection, its Trust Anchors and Trust Marks, a resolution, and its
 * settings.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class OidfedPage {
  /**
   * Draws the page's body from its view.
   *
   * @param view - the answer of the page's management API operation
   * @param ctx - the render context (`WebKit.context()`); the default one
   *   when a caller has none
   * @returns the body as HTML
   */
  static render(view: Json, ctx?: Json): string {
    return OidfedPage.body(view, (ctx || kit.context()).t);
  }

  /**
   * Draws a value as `<code>`, escaped.
   *
   * @param value - the value
   * @returns the markup
   */
  static code(value: Json): string {
    return '<code>' + esc(value == null ? '' : String(value)) + '</code>';
  }

  /**
   * Draws a quiet placeholder such as "none".
   *
   * @param text - the placeholder; "none" when empty
   * @returns the markup
   */
  static none(text: string): string {
    return '<span class="sub">' + esc(text || 'none') + '</span>';
  }

  /**
   * Draws a hidden form field.
   *
   * @param name - the field's name
   * @param value - its value
   * @returns the markup
   */
  static hidden(name: string, value: Json): string {
    return '<input type="hidden" name="' + esc(name) + '" value="' +
           esc(String(value == null ? '' : value)) + '">';
  }

  // One POST control: the action, its hidden fields, the visible ones and a
  // button.
  /**
   * Draws one POST control: the action, its hidden fields, the visible ones and
   * a button.
   *
   * @param action - the action's name
   * @param fields - the fields' markup
   * @param button - the button's label
   * @param danger - whether the button is drawn as dangerous
   * @returns the markup
   */
  static form(action: string, fields: string, button: string,
       danger?: boolean): string {
    return '<form method="post" action="/admin/oidfed" class="inline">' +
           this.hidden('action', action) + fields + ' <button type="submit"' +
           (danger ? ' class="danger"' : '') + '>' + esc(button) +
           '</button></form>';
  }

  /**
   * Draws the section about this realm as a federation entity.
   *
   * @param json - `oidfed.view()`'s answer
   * @param t - the page's translator
   * @returns the markup
   */
  static sectionEntity(json: Json, t: Json): string {
    const self = this;
    const endpoints = Object.keys(json.endpoints).map(function (k: string) {
      return '<tr><th>' + esc(k) + '</th><td>' + self.code(json.endpoints[k]) +
             '</td></tr>';
    }).join('');
    return '<h2>' + t.html('consoleOidfed.entityHeading') +
      '</h2><table class="kv">' +
      '<tr><th>' + t.html('consoleOidfed.entityIdentifier') + '</th><td>' +
      this.code(json.entityId) +
      '</td></tr><tr><th>' + t.html('consoleOidfed.role') +
      '</th><td><strong>' + esc(json.role) +
      '</strong></td></tr><tr><th>' + t.html('consoleOidfed.authorityHints') +
      '</th><td>' +
      (json.authorityHints.length
        ? json.authorityHints.map(this.code.bind(this)).join('<br>')
        : this.none(t.text('consoleOidfed.noneTrustAnchor'))) +
      '</td></tr>' +
      '<tr><th>' + t.html('consoleOidfed.everyRealmSubordinate') +
      '</th><td>' +
      (json.realmsAreSubordinates ? t.html('consoleOidfed.yes')
                                  : t.html('consoleOidfed.no')) +
      '</td></tr></table>' +
      '<h3>' + t.html('consoleOidfed.endpoints') +
      '</h3><table class="kv">' + endpoints + '</table>' +
      (json.entityConfigurationProblem
        ? kit.warn(esc(json.entityConfigurationProblem)) : '') +
      (json.entityConfiguration
        ? '<details><summary>' +
          t.html('consoleOidfed.entityConfigurationClaims') + '</summary>' +
          '<pre>' + esc(JSON.stringify(json.entityConfiguration, null, 2)) +
          '</pre></details>' : '');
  }

  /**
   * Draws the Federation Entity Keys section.
   *
   * @param json - `oidfed.view()`'s answer
   * @param t - the page's translator
   * @returns the markup
   */
  static sectionKeys(json: Json, t: Json): string {
    const self = this;
    const rows = json.keys.length ? json.keys.map(function (k: Json) {
      const control = k.state === 'retired' && !k.revokedAt
        ? self.form('revoke-key', self.hidden('kid', k.kid) +
            '<select name="reason"><option>superseded</option>' +
            '<option>compromised</option><option>unspecified</option>' +
            '</select>', t.text('consoleOidfed.revoke'), true)
        : '';
      return '<tr><td>' + self.code(k.kid) + '</td><td>' + esc(k.alg) +
        '</td><td>' + esc(k.state) + (k.revokedAt
          ? t.html('consoleOidfed.revokedBecause',
                   { reason: k.revokedReason })
          : '') + '</td><td>' +
        esc(k.createdAt || '') + '</td><td>' + esc(k.publishedUntil || '') +
        '</td><td>' + (k.sealed ? t.html('consoleOidfed.sealed')
                                : t.html('consoleOidfed.notSealed')) +
        '</td><td>' +
        control + '</td></tr>';
    }).join('') : '<tr><td colspan="7" class="sub">' +
      t.html('consoleOidfed.noKey') + '</td></tr>';
    return '<h2>' + t.html('consoleOidfed.keysHeading') + '</h2>' +
      kit.note(t.html('consoleOidfed.keysNote', { alg: json.signingAlg })) +
      '<table><thead><tr><th>kid</th><th>' +
      t.html('consoleOidfed.thAlgorithm') + '</th><th>' +
      t.html('consoleOidfed.thState') + '</th>' +
      '<th>' + t.html('consoleOidfed.thMade') + '</th><th>' +
      t.html('consoleOidfed.thPublishedUntil') + '</th><th>' +
      t.html('consoleOidfed.thAtRest') + '</th><th></th></tr>' +
      '</thead><tbody>' + rows + '</tbody></table>' +
      this.form('rotate-key', '', t.text('consoleOidfed.rotateNow')) + ' ' +
      // The word to type stays `compromised` in every language: it is what
      // the server compares the confirmation with (#539).
      this.form('rotate-key', this.hidden('emergency', 'true') +
        ' <input name="confirm" placeholder="' +
        attr(t.text('consoleOidfed.typeCompromised')) + '" required>',
        t.text('consoleOidfed.emergencyRotation'), true);
  }

  /**
   * Draws the subordinates section, with each one's history and controls.
   *
   * @param json - `oidfed.view()`'s answer
   * @param t - the page's translator
   * @returns the markup
   */
  static sectionSubordinates(json: Json, t: Json): string {
    const self = this;
    const reasonField = '<input name="reason" placeholder="' +
                        attr(t.text('consoleOidfed.phReason')) + '" ' +
                        'size="18"> <input name="informationUri" ' +
                        'placeholder="' +
                        attr(t.text('consoleOidfed.phInformationUri')) +
                        '" size="18">';
    const rows = json.subordinates.length
      ? json.subordinates.map(function (s: Json) {
        const who = self.hidden('entityId', s.entityId);
        const status = s.suspended
          ? t.html('consoleOidfed.suspendedAt',
                   { at: String(s.suspended.at || '') }) +
            (s.suspended.reason ? ' — ' + esc(s.suspended.reason) : '')
          : t.html('consoleOidfed.active');
        const acts = (s.suspended
          ? self.form('reinstate-subordinate', who + ' ' + reasonField,
                      t.text('consoleOidfed.reinstate'))
          : self.form('suspend-subordinate', who + ' ' + reasonField,
                      t.text('consoleOidfed.suspend'), true)) +
          (s.implicit ? '' : ' ' + self.form('remove-subordinate',
            who + ' ' + reasonField, t.text('consoleOidfed.revoke'), true));
        // `constraints` is the statement's member, so it is not translated.
        return '<tr><td>' + self.code(s.entityId) + '</td><td>' +
          (s.localRealm ? t.html('consoleOidfed.realmNamed',
                                 { realm: s.localRealm }) +
                          (s.implicit ? t.html('consoleOidfed.everyRealm')
                                      : '')
                        : esc((s.kids || []).join(', '))) + '</td><td>' +
          esc((s.entityTypes || []).join(', ')) + '</td><td>' +
          (s.metadataPolicy ? t.html('consoleOidfed.yes') : '') +
          (s.constraints ? ' constraints' : '') +
          '</td><td>' + status + self.history(s.events, t) + '</td><td>' +
          acts + '</td></tr>';
      }).join('')
      : '<tr><td colspan="6" class="sub">' +
        t.html('consoleOidfed.noSubordinates') + '</td></tr>';
    return '<h2>' + t.html('consoleOidfed.subordinatesHeading') + '</h2>' +
      kit.note(t.html('consoleOidfed.subordinatesNote')) +
      '<table><thead><tr><th>' + t.html('consoleOidfed.thEntity') +
      '</th><th>' + t.html('consoleOidfed.thKeys') + '</th><th>' +
      t.html('consoleOidfed.thTypes') + '</th>' +
      '<th>' + t.html('consoleOidfed.thPolicy') + '</th><th>' +
      t.html('consoleOidfed.thStatus') +
      '</th><th></th></tr></thead><tbody>' + rows +
      '</tbody></table>' + this.sectionFormer(json, t) +
      '<form method="post" action="/admin/oidfed">' +
      this.hidden('action', 'add-subordinate') +
      '<p><input name="entityId" placeholder="https://entity.example" ' +
      'required size="50"> <label><input type="checkbox" name="fetchJwks">' +
      ' ' + t.html('consoleOidfed.fetchJwks') + '</label> <label>' +
      '<input type="checkbox" name="intermediate"> ' +
      t.html('consoleOidfed.anIntermediate') + '</label>' +
      '</p><p><textarea name="jwks" rows="3" cols="80" placeholder="' +
      attr(t.text('consoleOidfed.phJwks')) + '"></textarea></p>' +
      '<p><textarea name="metadataPolicy" ' +
      'rows="3" cols="80" placeholder="metadata_policy (JSON)"></textarea>' +
      '</p><p><textarea name="constraints" rows="2" cols="80" ' +
      'placeholder="constraints (JSON)"></textarea></p>' +
      '<p><input name="eventDescription" placeholder="' +
      attr(t.text('consoleOidfed.phEventDescription')) +
      '" size="40"> <input name="informationUri" ' +
      'placeholder="' + attr(t.text('consoleOidfed.phInformationUri')) +
      '" size="30"></p>' +
      '<p><button type="submit">' +
      t.html('consoleOidfed.registerSubordinate') + '</button></p></form>';
  }

  // One subordinate's history (#137), folded: a <details> needs no script.
  /**
   * Draws one subordinate's history, folded in a `<details>`.
   *
   * @param events - the subordinate's events
   * @param t - the page's translator
   * @returns the markup
   */
  static history(events: Json, t: Json): string {
    const list: Json[] = Array.isArray(events) ? events : [];
    if (!list.length) {
      return '';
    }
    const rows = list.map(function (e: Json): string {
      return '<tr><td>' + esc(new Date(Number(e.iat) * 1000).toISOString()) +
        '</td><td><code>' + esc(e.event) + '</code></td><td>' +
        esc(e.event_description || '') +
        (e.information_uri ? ' <a href="' + esc(e.information_uri) +
                             '">' + t.html('consoleOidfed.information') +
                             '</a>' : '') + '</td></tr>';
    }).join('');
    return '<details><summary>' +
           t.html('consoleOidfed.historyCount', { n: list.length }) +
           '</summary>' +
           '<table><tbody>' + rows + '</tbody></table></details>';
  }

  // The subordinates this realm revoked, whose histories it keeps (#137).
  /**
   * Draws the subordinates this realm revoked, whose histories it keeps.
   *
   * @param json - `oidfed.view()`'s answer
   * @param t - the page's translator
   * @returns the markup
   */
  static sectionFormer(json: Json, t: Json): string {
    const self = this;
    const former: Json[] = json.formerSubordinates || [];
    if (!former.length) {
      return '';
    }
    const rows = former.map(function (f: Json): string {
      return '<tr><td>' + self.code(f.entityId) + '</td><td>' +
        (f.localRealm ? t.html('consoleOidfed.realmDeleted',
                               { realm: f.localRealm })
                      : t.html('consoleOidfed.revoked')) +
        self.history(f.events, t) + '</td></tr>';
    }).join('');
    return '<h3>' + t.html('consoleOidfed.formerHeading') +
           '</h3><table><thead><tr><th>' +
           t.html('consoleOidfed.thEntity') + '</th>' +
           '<th>' + t.html('consoleOidfed.thHistory') +
           '</th></tr></thead><tbody>' + rows + '</tbody></table>';
  }

  // The Entity Collection (#136): the crawl kept, and Crawl now.
  /**
   * Draws the Entity Collection section: the last crawl, and Crawl now.
   *
   * @param json - `oidfed.view()`'s answer
   * @param t - the page's translator
   * @returns the markup
   */
  static sectionCollection(json: Json, t: Json): string {
    const c = json.collection || {};
    const crawl = c.crawl;
    const kept = crawl
      ? '<table><tbody><tr><th>' + t.html('consoleOidfed.crawled') +
        '</th><td>' + esc(crawl.crawledAt) +
        '</td></tr><tr><th>' + t.html('consoleOidfed.crawlFor') +
        '</th><td>' + this.code(crawl.entityId) +
        (crawl.forThisIdentifier ? '' : ' ' +
                                        t.html('consoleOidfed.notThisId')) +
        '</td></tr><tr><th>' + t.html('consoleOidfed.entities') +
        '</th><td>' + esc(String(crawl.entities)) +
        (crawl.truncated ? ' ' + t.html('consoleOidfed.stoppedAtBound')
                         : '') + '</td></tr>' +
        (crawl.problems.length
          ? '<tr><th>' + t.html('consoleOidfed.leftOut') +
            '</th><td><details><summary>' +
            esc(String(crawl.problems.length)) + '</summary><ul>' +
            crawl.problems.map(function (p: string): string {
              return '<li>' + esc(p) + '</li>';
            }).join('') + '</ul></details></td></tr>' : '') +
        '</tbody></table>'
      : '<p class="sub">' + t.html('consoleOidfed.noCrawl') + '</p>';
    // `jobOff` is the view's own sentence, drawn as it comes (#539), and
    // kept out of the message: a parameter's apostrophe is escaped as
    // `&#39;` where esc() writes `&apos;`, which would change the page.
    return '<h2>' + t.html('consoleOidfed.collectionHeading') + '</h2>' +
      kit.note(t.html('consoleOidfed.collectionNote') + ' ' +
        (c.jobOff ? t.html('consoleOidfed.crawlOff') + esc(c.jobOff) +
                    t.html('consoleOidfed.crawlOffEnd')
                  : t.html('consoleOidfed.crawlEvery',
                           { s: String(c.crawlEveryS) }))) +
      kept + this.form('crawl-collection', '',
                       t.text('consoleOidfed.crawlNow'));
  }

  /**
   * Draws the Trust Anchors section.
   *
   * @param json - `oidfed.view()`'s answer
   * @param t - the page's translator
   * @returns the markup
   */
  static sectionAnchors(json: Json, t: Json): string {
    const self = this;
    const rows = json.trustAnchors.map(function (a: Json) {
      return '<tr><td>' + self.code(a.entityId) + '</td><td>' +
        (a.localRealm ? t.html('consoleOidfed.realmNamed',
                               { realm: a.localRealm })
                      : esc((a.kids || []).join(', '))) + '</td><td>' +
        (a.localRealm ? '' : self.form('remove-trust-anchor',
          self.hidden('entityId', a.entityId),
          t.text('consoleOidfed.remove'), true)) +
        '</td></tr>';
    }).join('');
    return '<h2>' + t.html('consoleOidfed.anchorsHeading') + '</h2>' +
      kit.note(t.html('consoleOidfed.anchorsNote')) +
      '<table><thead><tr><th>' + t.html('consoleOidfed.thAnchor') +
      '</th><th>' + t.html('consoleOidfed.thKeys') +
      '</th><th></th></tr></thead>' +
      '<tbody>' + (rows || '<tr><td colspan="3" class="sub">' +
                   t.html('consoleOidfed.noneRow') + '</td></tr>') +
      '</tbody></table>' +
      '<form method="post" action="/admin/oidfed">' +
      this.hidden('action', 'add-trust-anchor') +
      '<p><input name="entityId" placeholder="https://anchor.example" ' +
      'required size="50"> <label><input type="checkbox" name="fetchJwks">' +
      ' ' + t.html('consoleOidfed.fetchJwks') + '</label></p><p>' +
      '<textarea name="jwks" rows="3" cols="80" placeholder="' +
      attr(t.text('consoleOidfed.phJwks')) +
      '"></textarea></p><p><button type="submit">' +
      t.html('consoleOidfed.trustIt') +
      '</button></p></form>';
  }

  /**
   * Draws the Trust Marks section.
   *
   * @param json - `oidfed.view()`'s answer
   * @param t - the page's translator
   * @returns the markup
   */
  static sectionMarks(json: Json, t: Json): string {
    const self = this;
    // `type`, not `t`, since #539: `t` is the page's translator, always.
    const types = json.markTypes.map(function (type: Json) {
      return '<tr><td>' + self.code(type.type) + '</td><td>' +
        esc(type.lifetimeS) +
        ' s</td><td>' +
        (type.delegation ? t.html('consoleOidfed.delegated') : '') +
        '</td><td>' +
        self.form('issue-trust-mark', self.hidden('type', type.type) +
          ' <input name="sub" placeholder="https://entity.example" ' +
          'required>', t.text('consoleOidfed.issue')) + ' ' +
        self.form('remove-mark-type', self.hidden('type', type.type),
                  t.text('consoleOidfed.remove'), true) + '</td></tr>';
    }).join('');
    const issued = json.issuedMarks.map(function (m: Json) {
      return '<tr><td>' + self.code(m.type) + '</td><td>' + self.code(m.sub) +
        '</td><td>' + esc(m.status) + '</td><td>' + esc(m.expiresAt || '') +
        '</td><td>' + (m.status === 'revoked' ? '' :
          self.form('revoke-trust-mark', self.hidden('id', m.id),
                    t.text('consoleOidfed.revoke'), true)) + '</td></tr>';
    }).join('');
    const held = json.heldMarks.map(function (m: Json) {
      return '<tr><td>' + self.code(m.type) + '</td><td>' + self.code(m.iss) +
        '</td><td>' + esc(m.expiresAt || '') + '</td><td>' +
        self.form('remove-held-mark', self.hidden('id', m.id),
                  t.text('consoleOidfed.remove'), true) + '</td></tr>';
    }).join('');
    const policies = json.markPolicies.map(function (p: Json) {
      return '<tr><td>' + self.code(p.type) + '</td><td>' +
        esc((p.issuers || []).join(', ') ||
            t.text('consoleOidfed.anybody')) + '</td><td>' +
        esc(p.owner || '') + '</td><td>' + self.form('remove-mark-policy',
          self.hidden('type', p.type), t.text('consoleOidfed.remove'),
          true) + '</td></tr>';
    }).join('');
    const empty = function (n: number): string {
      return '<tr><td colspan="' + n + '" class="sub">' +
             t.html('consoleOidfed.noneRow') + '</td></tr>';
    };
    return '<h2>' + t.html('consoleOidfed.marksHeading') + '</h2>' +
      kit.note(t.html('consoleOidfed.marksNote')) +
      '<h3>' + t.html('consoleOidfed.typesIssued') +
      '</h3><table><thead><tr><th>' + t.html('consoleOidfed.thType') +
      '</th>' +
      '<th>' + t.html('consoleOidfed.thLifetime') +
      '</th><th></th><th></th></tr></thead><tbody>' +
      (types || empty(4)) + '</tbody></table>' +
      '<form method="post" action="/admin/oidfed">' +
      this.hidden('action', 'add-mark-type') +
      '<p><input name="type" placeholder="https://federation.example/marks/' +
      'x" required size="50"> <input name="lifetimeS" type="number" ' +
      'min="60" placeholder="' + attr(t.text('consoleOidfed.phLifetime')) +
      '"> <input name="logoUri" ' +
      'placeholder="logo_uri"> <input name="ref" placeholder="ref"></p>' +
      '<p><textarea name="delegation" rows="2" cols="80" placeholder="' +
      attr(t.text('consoleOidfed.phDelegation')) +
      '"></textarea></p><p><button type="submit">' +
      t.html('consoleOidfed.issueThisType') +
      '</button></p></form>' +
      '<h3>' + t.html('consoleOidfed.issuedHeading') +
      '</h3><table><thead><tr><th>' + t.html('consoleOidfed.thType') +
      '</th><th>' + t.html('consoleOidfed.thTo') + '</th><th>' +
      t.html('consoleOidfed.thStatus') +
      '</th><th>' + t.html('consoleOidfed.thExpires') +
      '</th><th></th></tr></thead><tbody>' +
      (issued || empty(5)) + '</tbody></table>' +
      '<h3>' + t.html('consoleOidfed.carriedHeading') +
      '</h3><table><thead><tr><th>' + t.html('consoleOidfed.thType') +
      '</th>' +
      '<th>' + t.html('consoleOidfed.thIssuer') + '</th><th>' +
      t.html('consoleOidfed.thExpires') +
      '</th><th></th></tr></thead><tbody>' +
      (held || empty(4)) + '</tbody></table>' +
      this.form('add-held-mark', '<input name="trustMark" size="60" ' +
                'placeholder="' + attr(t.text('consoleOidfed.phTrustMark')) +
                '" required>', t.text('consoleOidfed.carryIt')) +
      '<h3>' + t.html('consoleOidfed.policyHeading') +
      '</h3><table><thead><tr>' +
      '<th>' + t.html('consoleOidfed.thType') + '</th><th>' +
      t.html('consoleOidfed.thIssuers') + '</th><th>' +
      t.html('consoleOidfed.thOwner') +
      '</th><th></th></tr></thead>' +
      '<tbody>' + (policies || empty(4)) + '</tbody></table>' +
      '<form method="post" action="/admin/oidfed">' +
      this.hidden('action', 'set-mark-policy') +
      '<p><input name="type" placeholder="' +
      attr(t.text('consoleOidfed.phType')) + '" required size="40"> ' +
      '<input name="issuers" placeholder="' +
      attr(t.text('consoleOidfed.phIssuers')) +
      '" size="40"> <input name="ownerSub" placeholder="' +
      attr(t.text('consoleOidfed.phOwnerEntity')) +
      '"></p><p><textarea name="ownerJwks" rows="2" cols="80" ' +
      'placeholder="' + attr(t.text('consoleOidfed.phOwnerJwks')) +
      '"></textarea></p><p><button ' +
      'type="submit">' + t.html('consoleOidfed.setPolicy') +
      '</button></p></form>';
  }

  /**
   * Draws the Resolve an entity section, and the last resolution's result.
   *
   * @param json - `oidfed.view()`'s answer
   * @param extra - a resolution to show, if any
   * @param t - the page's translator
   * @returns the markup
   */
  static sectionResolve(json: Json, extra: Json, t: Json): string {
    const shown = extra ? '<pre>' + esc(JSON.stringify(extra, null, 2)) +
                          '</pre>' : '';
    return '<h2>' + t.html('consoleOidfed.resolveHeading') + '</h2>' +
      kit.note(t.html('consoleOidfed.resolveNote',
                      { n: String(json.resolutions.length) })) +
      this.form('resolve', '<input name="sub" placeholder="https://entity.' +
                'example" required size="50"> <input name="trustAnchor" ' +
                'placeholder="' + attr(t.text('consoleOidfed.phTrustAnchor')) +
                '" size="40">', t.text('consoleOidfed.resolve')) +
      shown;
  }

  // THE PAGE'S BODY (#446), one method so that it can be one renderer. A
  // resolution the reader just asked for is the view's `resolution`.
  /**
   * Draws the page's body.
   *
   * @param json - the view, with `resolution` when one was just made
   * @param t - the page's translator
   * @returns the body as HTML
   */
  static body(json: Json, t: Json): string {
    const inner =
      kit.note(t.html('consoleOidfed.intro', { role: json.role })) +
      this.sectionEntity(json, t) + this.sectionKeys(json, t) +
      this.sectionSubordinates(json, t) + this.sectionCollection(json, t) +
      this.sectionAnchors(json, t) +
      this.sectionMarks(json, t) +
      this.sectionResolve(json, json.resolution, t) +
      SettingsForms.forms(json.settings, '/admin/oidfed') +
      '<p class="links"><a href="/admin/oidfed?format=json">JSON</a> · ' +
      '<code>GET /admin-api/oidfed</code> · <a href="' +
      esc(json.configurationUrl) + '">' +
      t.html('consoleOidfed.linkEntityConfiguration') + '</a> · ' +
      '<a href="/admin/federation">' + t.html('consoleOidfed.linkFederation') +
      '</a> · <a ' +
      'href="/admin/error-codes">' + t.html('consoleOidfed.linkErrorCodes') +
      '</a></p>';
    return inner;
  }
}

export = OidfedPage;
